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
#include <memory>

// ----------------- constants -----------------
constexpr int MAX_VPAGES = 64;   
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
    // stats
    unsigned long unmaps{0}, maps{0}, ins{0}, outs{0};
    unsigned long fins{0}, fouts{0}, zeros{0};
    unsigned long segv{0}, segprot{0};
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

// ---- global stats ----
static unsigned long instr_cnt=0, ctx_cnt=0, exit_cnt=0, total_cost=0;

// cost constants
constexpr int COST_MAP=410, 
COST_UNMAP=440, 
COST_IN=3210,
COST_OUT=2850,
COST_FIN=3350, 
COST_FOUT=2930, 
COST_ZERO=160,
COST_SEGV=444,
COST_SEGPROT=414,
COST_CTXSW=140;

// ----------------- dump helpers ----------------
static void dump_pt(const Process& p)
{
    std::cout << "PT[" << p.pid << "]: ";
    for (int i = 0; i < MAX_VPAGES; ++i) {
        const pte_t& e = p.page_table[i];

        // print entry
        if (!e.PRESENT) {
            std::cout << (e.PAGEDOUT ? "#" : "*");
        } else {
            std::cout << i << ":";
            std::cout << (e.REFERENCED ? "R" : "-");
            std::cout << (e.MODIFIED   ? "M" : "-");
            std::cout << (e.PAGEDOUT   ? "S" : "-");
        }

        // delimiter between columns (but not after the last one)
        if (i != MAX_VPAGES - 1) std::cout << ' ';
    }
    std::cout << "\n";
}

static void dump_all_pts(const std::vector<Process>& procs)
{
    for (const auto& p : procs) dump_pt(p);
}

static void dump_frame_table()
{
    std::cout << "FT: ";
    for (size_t i = 0; i < frame_table.size(); ++i) {
        const frame_t& f = frame_table[i];
        if (f.proc == nullptr) std::cout << '*';
        else std::cout << f.proc->pid << ':' << f.vpage;

        if (i != frame_table.size() - 1) std::cout << ' ';
    }
    std::cout << "\n";
}

// ------------ Pager hierarchy -------------
class Pager { 
    public: virtual frame_t* select_victim_frame()=0; 
    virtual ~Pager()=default; 
};

class FIFO : public Pager {
    std::deque<int> q;
public:
    frame_t* select_victim_frame() override {
        int idx = q.front();
        q.pop_front();
        q.push_back(idx);               // keep circular order
        return &frame_table[idx];
    }

    void frame_allocated(int idx) {
        q.push_back(idx);
    }
};

static std::unique_ptr<Pager> pager;

static frame_t* get_free_frame()
{
    // return a frame from the free list if available
    if (!free_list.empty()) {
        int idx = free_list.front();
        free_list.pop_front();

        // let the pager (e.g., FIFO) know about the new allocation
        if (auto* fifo = dynamic_cast<FIFO*>(pager.get())) {
            fifo->frame_allocated(idx);
        }
        return &frame_table[idx];
    }

    // otherwise ask the pager for a victim frame
    return pager->select_victim_frame();
}

static const VMA* find_vma(const Process& proc, int vp)
{
    for (const auto& v : proc.vmas) {
        if (vp >= v.start_vpage && vp <= v.end_vpage) {
            return &v;
        }
    }
    return nullptr;
}

// ----------- eviction helper ------------
static void evict_frame(frame_t* frame)
{
    if (frame->proc == nullptr) return; // frame is free

    Process* victim_proc = frame->proc;
    pte_t& vpte         = victim_proc->page_table[frame->vpage];

    // UNMAP mandatory
    std::cout << " UNMAP " << victim_proc->pid << ":" << frame->vpage << "\n";
    victim_proc->unmaps++;
    total_cost += COST_UNMAP;

    // if modified, need to OUT/FOUT
    if (vpte.MODIFIED) {
        if (vpte.file_mapped) {
            std::cout << " FOUT\n";
            victim_proc->fouts++;
            total_cost += COST_FOUT;
        } else {
            std::cout << " OUT\n";
            victim_proc->outs++;
            total_cost += COST_OUT;
            vpte.PAGEDOUT = 1;    // remember it is on disk
        }
        vpte.MODIFIED = 0;  // page on disk is up-to-date
    }

    // clear mapping
    vpte.PRESENT = 0;
    victim_proc->page_table[frame->vpage].frame = 0;

    // mark frame as free for reuse (owner & vpage will be overwritten by caller)
    frame->proc  = nullptr;
    frame->vpage = -1;
}

static void handle_page_fault(Process& proc, int vpage, char op)
{
    // 1) Validate that the page belongs to one of the process VMAs
    const VMA* vma = find_vma(proc, vpage);
    if (vma == nullptr) {
        std::cout << " SEGV\n";       // segmentation violation
        proc.segv++;
        total_cost += COST_SEGV;
        return;                         // abort this memory reference
    }

    // 2) Populate invariant PTE bits from the VMA (only once)
    pte_t& pte = proc.page_table[vpage];
    if (!pte.WRITE_PROTECT && vma->write_protected) {
        pte.WRITE_PROTECT = 1;
    }
    if (!pte.file_mapped && vma->file_mapped) {
        pte.file_mapped = 1;
    }

    // 3) Obtain a physical frame (free or via pager replacement)
    frame_t* frame = get_free_frame();

    // if occupied, evict old mapping
    if (frame->proc != nullptr) {
        evict_frame(frame);
    }

    // now frame is free -> assign to current mapping
    frame->proc  = &proc;
    frame->vpage = vpage;

    // 4) Load or initialize the page contents
    if (pte.file_mapped) {
        std::cout << " FIN\n";        // file-mapped page: read from file
        proc.fins++;
        total_cost += COST_FIN;
    } else if (pte.PAGEDOUT) {
        std::cout << " IN\n";
        proc.ins++;
        total_cost += COST_IN;
    } else {
        std::cout << " ZERO\n";       // anonymous page: zero fill
        proc.zeros++;
        total_cost += COST_ZERO;
    }

    // 5) Finalize mapping
    pte.PRESENT = 1;
    pte.frame   = frame->fid;

    std::cout << " MAP " << frame->fid << "\n";
    proc.maps++;
    total_cost += COST_MAP;
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

    // 2. instantiate pager based on -a option 
    if(algo == 0) {
        // default when -a not given: FIFO
        pager = std::make_unique<FIFO>();
    } else if(algo == 'f' || algo == 'F') {
        pager = std::make_unique<FIFO>();
    } else {
        std::cerr << "error: pager algorithm '" << algo << "' is not implemented\n";
        return 1; // terminate instead of silently choosing another pager
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

    // ----------------- simulation loop -----------------
    int cur_pid = -1;
    for (size_t i = 0; i < insts.size(); ++i) {
        const auto& ins = insts[i];
        std::cout << i << ": ==> " << ins.op << " " << ins.arg << "\n";
        instr_cnt++; total_cost+=1;

        if(ins.op=='c'){ 
            /* cost of cycle already added, fixing to get proper total cost */ 
            ctx_cnt++; total_cost += COST_CTXSW - 1; 
            cur_pid=ins.arg; 
            continue; 
        }
        if(cur_pid<0) continue; Process& cur=procs[cur_pid];

        if(ins.op=='r'||ins.op=='w'){
            int vp=ins.arg; pte_t& pte=cur.page_table[vp];
            if(!pte.PRESENT) handle_page_fault(cur,vp,ins.op);
            if(pte.PRESENT){ pte.REFERENCED=1; if(ins.op=='w'){
                if(pte.WRITE_PROTECT){ std::cout<<" SEGPROT\n"; cur.segprot++; total_cost+=COST_SEGPROT; }
                else pte.MODIFIED=1; }} }

        if (dbg_x && cur_pid >= 0) dump_pt(cur);
        if(dbg_y) dump_all_pts(procs);
        if(dbg_f) dump_frame_table();
    }

    // ---- footer ----
    unsigned long total_outs = 0;
    for(const auto& p:procs){ 
        dump_pt(p); 
    }
    dump_frame_table();
    for(const auto& p:procs){ 
        std::cout<<"PROC["<<p.pid<<"]: U="<<p.unmaps<<" M="<<p.maps
        <<" I="<<p.ins<<" O="<<p.outs<<" FI="<<p.fins<<" FO="<<p.fouts<<" Z="<<p.zeros
        <<" SV="<<p.segv<<" SP="<<p.segprot<<"\n"; 
        total_outs += p.outs;
    }
    std::cout<<"TOTALCOST "<<instr_cnt<<' '<<ctx_cnt<<' '<<exit_cnt<<' '<<total_cost<<' '<<total_outs<<"\n";

    return 0;
}