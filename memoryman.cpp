#include <getopt.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <sstream>
#include <cctype>
#include <deque>
#include <array>

// ----------------- constants -----------------
constexpr int MAX_VPAGES = 64;   // fixed per spec
constexpr int MAX_FRAMES_LIMIT = 128; 
// ----------------- core MMU structs ----------
struct pte_t {
    unsigned int PRESENT       : 1;
    unsigned int REFERENCED    : 1;
    unsigned int MODIFIED      : 1;
    unsigned int WRITE_PROTECT : 1;
    unsigned int PAGEDOUT      : 1;
    unsigned int frame         : 7;   // 0-127
    unsigned int file_mapped   : 1;   // custom bit
    unsigned int : 14;                // reserved (must stay 0)
    unsigned int spare         : 5;   // still free
};
static_assert(sizeof(pte_t) == 4, "pte_t must be 32-bit");

// forward declaration so frame_t can reference Process
struct Process;

struct frame_t {
    int fid;                  // frame index
    Process* proc{};          // owning process (set later)
    int vpage{-1};            // mapped vpage
    unsigned int age{0};      // Aging algo helper
    unsigned long last_used{0}; // Working-Set helper
};

// ----------------- Data structures -----------------
struct VMA {
    int start_vpage;
    int end_vpage;
    bool write_protected;
    bool file_mapped;
};

struct Process {
    int pid;
    std::vector<VMA> vmas;
    std::array<pte_t, MAX_VPAGES> page_table{}; // zero-initialized PTEs
};

struct Instruction {
    char op;   // c/r/w/e
    int  arg;  // pid or vpage depending on op
};

// pretty-print helpers --------------------------------------------------
static std::ostream& operator<<(std::ostream& os, const VMA& v) {
    os << "[" << v.start_vpage << "-" << v.end_vpage
       << (v.write_protected ? " WP" : "  ")
       << (v.file_mapped     ? " FM" : "  ") << "]";
    return os;
}
static std::ostream& operator<<(std::ostream& os, const Process& p) {
    os << "PROC " << p.pid << " : ";
    for (size_t i = 0; i < p.vmas.size(); ++i) {
        os << p.vmas[i];
        if (i + 1 < p.vmas.size()) os << " ";
    }
    return os;
}

// Read next non-comment, non-blank line. Returns false on EOF.
static bool getline_skip_comments(std::istream& in, std::string& out)
{
    while (std::getline(in, out)) {
        size_t pos = out.find_first_not_of(" \t\r\n");
        if (pos == std::string::npos) continue;      // blank line
        if (out[pos] == '#')       continue;         // comment line
        out.erase(0, pos);                           // left-trim
        return true;
    }
    return false;
}

// ----------------- global tables --------------
static std::vector<frame_t> frame_table; // sized at runtime
static std::deque<int>      free_list;   // indices of free frames

// ----------------- dump helpers ----------------
static void dump_pt(const Process& p)
{
    std::cout << "PT " << p.pid << " : ";
    for (int i = 0; i < MAX_VPAGES; ++i) {
        const pte_t& e = p.page_table[i];
        if (!e.PRESENT) {
            std::cout << (e.PAGEDOUT ? "#" : "*") << " ";
        } else {
            std::cout << i << ":";
            std::cout << (e.REFERENCED ? "R" : "-");
            std::cout << (e.MODIFIED   ? "M" : "-");
            std::cout << (e.PAGEDOUT   ? "S" : "-") << " ";
        }
    }
    std::cout << "\n";
}

static void dump_all_pts(const std::vector<Process>& procs)
{
    for (const auto& p : procs) dump_pt(p);
}

static void dump_frame_table()
{
    std::cout << "FT : ";
    for (size_t i = 0; i < frame_table.size(); ++i) {
        const frame_t& f = frame_table[i];
        if (f.proc == nullptr) std::cout << "* ";
        else std::cout << f.proc->pid << ":" << f.vpage << " ";
    }
    std::cout << "\n";
}

int main(int argc, char* argv[])
{
    // 1. parse  -f<num_frames>  -a<algo>  [-o<opts>]
    int num_frames = 0; char algo = 0; std::string opts;
    int c; while ((c = getopt(argc, argv, "f:a:o:")) != -1) {
        if (c == 'f') num_frames = std::atoi(optarg);
        else if (c == 'a') algo = optarg[0];
        else if (c == 'o') opts = optarg;
    }
    if (optind + 2 != argc) {
        std::cerr << "usage: ./mmu -f# -aX [-oOPFS] input rfile\n";
        return 1;
    }
    if (num_frames <= 0 || num_frames > MAX_FRAMES_LIMIT) {
        std::cerr << "num_frames must be 1.." << MAX_FRAMES_LIMIT << "\n";
        return 1;
    }

    // allocate frame table & free list ----------------------------------
    frame_table.resize(num_frames);
    for (int i = 0; i < num_frames; ++i) {
        frame_table[i].fid = i;
        free_list.push_back(i);
    }

    /* 2. Decode debug flags in the -o string */
    bool dbg_x = opts.find('x') != std::string::npos;
    bool dbg_y = opts.find('y') != std::string::npos;
    bool dbg_f = opts.find('f') != std::string::npos;
    bool dbg_a = opts.find('a') != std::string::npos;

    // ----------------- 3. parse INPUT FILE -----------------
    std::ifstream fin(argv[optind]);
    if (!fin) { std::perror(argv[optind]); return 1; }

    std::string line;
    if (!getline_skip_comments(fin, line)) {
        std::cerr << "Malformed input: missing process count\n";
        return 1;
    }
    int num_procs = std::stoi(line);

    std::vector<Process> procs(num_procs);
    for (int pid = 0; pid < num_procs; ++pid) {
        procs[pid].pid = pid;
        if (!getline_skip_comments(fin, line)) { std::cerr << "Unexpected EOF"; return 1; }
        int num_vmas = std::stoi(line);
        for (int i = 0; i < num_vmas; ++i) {
            if (!getline_skip_comments(fin, line)) { std::cerr << "Unexpected EOF"; return 1; }
            std::istringstream iss(line);
            VMA v{};
            iss >> v.start_vpage >> v.end_vpage >> v.write_protected >> v.file_mapped;
            procs[pid].vmas.push_back(v);
        }
    }

    std::vector<Instruction> insts;
    while (getline_skip_comments(fin, line)) {
        Instruction ins{};
        if (line[0] == 'c' && line.size() > 1 && std::isdigit(line[1])) {
            ins.op = 'c';
            ins.arg = std::stoi(line.substr(1));
        } else {
            std::istringstream iss(line);
            iss >> ins.op >> ins.arg;
        }
        insts.push_back(ins);
    }

    // --------------- sanity print (temporary) ----------------
    std::cout << "Read " << procs.size() << " processes\n";
    for (const auto& p : procs)
        std::cout << "  " << p << "\n";
    std::cout << "Read " << insts.size() << " instructions\n\n";

    int cur_pid = -1;
    // ----------------- dummy walk to show desired output format ---------
    for (size_t i = 0; i < insts.size(); ++i) {
        const auto& ins = insts[i];
        std::cout << i << ": ==> " << ins.op << " " << ins.arg << "\n";
        if (ins.op == 'c') cur_pid = ins.arg;
        if (dbg_x && cur_pid >= 0) dump_pt(procs[cur_pid]);
        if (dbg_y) dump_all_pts(procs);
        if (dbg_f) dump_frame_table();
    }

    return 0;
}