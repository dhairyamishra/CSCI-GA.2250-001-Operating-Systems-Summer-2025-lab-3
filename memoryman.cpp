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
#include <algorithm>
#include <climits>

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

static bool dbg_a_enabled = false;   // turned on by -oa
static void aselect_log(const std::string& msg)
{
    if (dbg_a_enabled) std::cout << "ASELECT " << msg << "\n";
}

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
    unsigned long unmaps{0}, maps{0}, ins{0}, outs{0},fins{0}, fouts{0}, zeros{0},segv{0}, segprot{0};
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

// Re-usable helper: remove a frame id from free_list if present
static inline void remove_from_free_list(int fid){
    for(auto it=free_list.begin(); it!=free_list.end(); ++it){
        if(*it==fid){ free_list.erase(it); break; }
    }
}

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
COST_CTXSW=140,
COST_EXIT=1430;

static std::vector<int> randvals;
static size_t rand_ofs = 0;

static inline int myrandom(int randomnumber); 

static void load_rand_file(const std::string& fname) {
    std::ifstream fin(fname);
    if(!fin) { std::cerr << "cannot open randfile " << fname << "\n"; std::exit(1);}    
    size_t n; fin >> n;
    randvals.reserve(n);
    int x; while(fin >> x) randvals.push_back(x);
    rand_ofs = 0;
}

static inline int myrandom(int randomnumber) {       // returns 0..randomnumber-1
    int r = randvals[rand_ofs] % randomnumber;
    rand_ofs = (rand_ofs + 1) % randvals.size();
    return r;
}
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
    size_t hand = 0;                // next frame to evict
public:
    frame_t* select_victim_frame() override {
        frame_t* victim = &frame_table[hand];
        hand = (hand + 1) % frame_table.size();   // round-robin
        return victim;
    }

    /* not needed after updating FIFO to use hand to check for free frames delete later */
    void frame_allocated(int) {}    // not used
    void frame_freed(int)     {}    // not used
};

class Clock : public Pager {
    size_t hand = 0; // points to next frame to examine
public:
    frame_t* select_victim_frame() override {
        const size_t N = frame_table.size();
        while (true) {
            frame_t* f = &frame_table[hand];
            // wrap hand for next call already – easy on brain
            hand = (hand + 1) % N;

            // free frame is impossible here (free_list would have supplied it),
            // but handle gracefully
            if (f->proc == nullptr)
                return f;

            pte_t& pte = f->proc->page_table[f->vpage];
            if (pte.REFERENCED) {
                pte.REFERENCED = 0;     // give second chance
                continue;               // advance hand
            }
            // found victim
            return f;
        }
    }
};

class NRU : public Pager {
    size_t hand = 0;
    unsigned long last_reset_inst = 0;

public:
    frame_t* select_victim_frame() override {
        const size_t N = frame_table.size();
        std::array<frame_t*,4> first{};           // first frame of each class
        bool reset_now = (instr_cnt - last_reset_inst) >=48;

        size_t start = hand;
        size_t scanned = 0;
        int    lowest_class = 3;                  // track lowest class seen

        /* ---------- PASS 1 : classify ---------- */
        for (size_t i = 0; i < N; ++i) {
            size_t idx   = (hand + i) % N;
            frame_t* frm = &frame_table[idx];
            if (!frm->proc) continue;

            pte_t& pte = frm->proc->page_table[frm->vpage];
            int cls    = (pte.REFERENCED << 1) | pte.MODIFIED;
            if (!first[cls]) first[cls] = frm;
            lowest_class = std::min(lowest_class, cls);

            scanned++;
            if (cls == 0 && !reset_now) {         // perfect victim found
                hand = (idx + 1) % N;
                aselect_log(std::to_string(start) + " "
                        + (reset_now ? "1" : "0") + " | "
                        + std::to_string(lowest_class) + " "
                        + std::to_string(frm->fid) + " "
                        + std::to_string(scanned));
                return frm;
            }
        }

        /* ---------- PASS 2 : reset R bits if needed ---------- */
        if (reset_now) {
            for (frame_t& f : frame_table)
                if (f.proc) f.proc->page_table[f.vpage].REFERENCED = 0;
            last_reset_inst = instr_cnt;
        }

        /* ---------- choose lowest non-empty class ---------- */
        for (int c = 0; c < 4; ++c)
            if (first[c]) {
                hand = (first[c]->fid + 1) % N;
                aselect_log(std::to_string(start) + " "
                        + (reset_now ? "1" : "0") + " | "
                        + std::to_string(lowest_class) + " "
                        + std::to_string(first[c]->fid) + " "
                        + std::to_string(scanned));
                return first[c];
            }

        /* never reached, but keep compiler happy */
        hand = (hand + 1) % N;
        return &frame_table[hand];
    }

};

/* ---------------- Aging Pager ---------------- */
class Aging : public Pager {
    size_t hand = 0;                       // next frame to inspect
public:
    frame_t* select_victim_frame() override
    {
        const size_t N = frame_table.size();
        frame_t* victim       = nullptr;
        unsigned int min_age  = 0xFFFFFFFF;
        size_t start = hand;

        /* scan every frame exactly once */
        for (size_t i = 0; i < N; ++i) {
            size_t idx   = (hand + i) % N;
            frame_t* frm = &frame_table[idx];

            pte_t& pte = frm->proc->page_table[frm->vpage];

            /* --- aging update: shift right, insert REF into MSB --- */
            frm->age >>= 1;
            if (pte.REFERENCED) {
                frm->age |= 0x80000000u;
                pte.REFERENCED = 0;       // clear R after use
            }

            if (frm->age < min_age) {
                min_age = frm->age;
                victim  = frm;
            }
        }

        /* debug trace */
        if (dbg_a_enabled) {
            std::ostringstream os;
            os << "ASELECT " << start << "-" << ((hand + N - 1) % N) << " |";
            for (size_t i = 0; i < N; ++i) {
                size_t idx = (start + i) % N;
                os << ' ' << idx << ':' << std::hex << frame_table[idx].age;
            }
            os << " | " << victim->fid;
            aselect_log(os.str());
        }

        /* advance hand for next call */
        hand = (victim->fid + 1) % frame_table.size();
        return victim;
    }
};


class RandomPager : public Pager {
public:
    frame_t* select_victim_frame() override {
        int idx = myrandom(frame_table.size());
        return &frame_table[idx];
    }
};

/* ---------------- Working Set Pager ---------------- */
class WorkingSet : public Pager {
    size_t hand = 0;
    static constexpr unsigned long TAU = 49;

public:
    frame_t* select_victim_frame() override {
        const size_t N = frame_table.size();
        size_t start = hand;
        size_t examined = 0;
        
        std::ostringstream os;
        if (dbg_a_enabled) {
            os << start << "-";
        }
        
        // First pass: look for R=0 and age > TAU
        while (true) {
            frame_t* f = &frame_table[hand];
            if (f->proc != nullptr) {
                pte_t& pte = f->proc->page_table[f->vpage];
                examined++;
                
                if (dbg_a_enabled) {
                    os << " " << hand << "(" << pte.REFERENCED << " "
                       << f->proc->pid << ":" << f->vpage << " "
                       << f->last_used << ")";
                }
                
                if (!pte.REFERENCED && (instr_cnt - f->last_used > TAU)) {
                    // Found working set victim
                    frame_t* victim = f;
                    size_t victim_frame = hand;  // Save current position before updating hand
                    hand = (hand + 1) % N;
                    
                    if (dbg_a_enabled) {
                        std::string debug_str = os.str();
                        size_t dash_pos = debug_str.find("-");
                        if (dash_pos != std::string::npos) {
                            debug_str.insert(dash_pos + 1, std::to_string(victim_frame));
                        }
                        debug_str += " STOP(" + std::to_string(examined) + ") | " + std::to_string(f->fid);
                        aselect_log(debug_str);
                    }
                    return victim;
                }
                
                if (pte.REFERENCED) {
                    // Give second chance: update time and clear R
                    f->last_used = instr_cnt;
                    pte.REFERENCED = 0;
                }
            }
            
            hand = (hand + 1) % N;
            if (hand == start) break; // Full circle
        }
        
        // Second pass: find oldest frame (fallback)
        frame_t* oldest = nullptr;
        unsigned long oldest_time = ULONG_MAX;
        
        for (size_t i = 0; i < N; ++i) {
            frame_t* fr = &frame_table[i];
            if (fr->proc && fr->last_used < oldest_time) {
                oldest_time = fr->last_used;
                oldest = fr;
            }
        }
        
        if (oldest) {
            hand = (oldest->fid + 1) % N;
            
            if (dbg_a_enabled) {
                std::string debug_str = os.str();
                size_t dash_pos = debug_str.find("-");
                if (dash_pos != std::string::npos) {
                    size_t end = (start + N - 1) % N;
                    debug_str.insert(dash_pos + 1, std::to_string(start));
                }
                debug_str += " | " + std::to_string(oldest->fid);
                aselect_log(debug_str);
            }
            return oldest;
        }
        
        // Ultimate fallback
        hand = (hand + 1) % N;
        return &frame_table[start];
    }
};

static std::unique_ptr<Pager> pager;

static frame_t* get_free_frame()
{
    if(!free_list.empty()){
        int idx = free_list.front();
        free_list.pop_front();
        return &frame_table[idx];
    }

    // need a victim chosen by pager
    frame_t* frame = pager->select_victim_frame();
    remove_from_free_list(frame->fid);  // ensure no duplicate in free_list
    return frame;
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
    // age has to be reset to 0 on each MAP operation
    frame->age  = 0; // reset age for aging algo
    frame->last_used = instr_cnt; // working set timestamp
    std::cout << " MAP " << frame->fid << "\n";
    proc.maps++;
    total_cost += COST_MAP;

    // inform FIFO once the frame is successfully mapped
    if(auto* fifo = dynamic_cast<FIFO*>(pager.get()))
        fifo->frame_allocated(frame->fid);
}

static void process_exit(Process& proc)
{
    std::vector<int> freed;
    for(int vp=0; vp<MAX_VPAGES; ++vp){
        pte_t& pte = proc.page_table[vp];
        if(!pte.PRESENT) continue;

        frame_t* frame = &frame_table[pte.frame];

        // UNMAP
        std::cout << " UNMAP " << proc.pid << ":" << vp << "\n";
        proc.unmaps++; total_cost += COST_UNMAP;

        // if modified, handle FOUT (do NOT OUT anonymous pages on exit)
        if(pte.MODIFIED){
            if(pte.file_mapped){
                std::cout << " FOUT\n";
                proc.fouts++; total_cost += COST_FOUT;
            }
            // anonymous dirty page is simply discarded; no OUT cost/stat
            pte.MODIFIED = 0;
        }

        // clear mapping in PTE and frame
        pte.PRESENT = 0;
        pte.REFERENCED = 0;
        pte.frame = 0;

        frame->proc = nullptr; frame->vpage = -1;

        // preserve the order of release
        freed.push_back(frame->fid);

        //reset the PTE to all zeros so that no PAGEDOUT
        pte = {};
    }

    // --- Return freed frames to free_list preserving FIFO chronology -----
    if (auto* fifo = dynamic_cast<FIFO*>(pager.get())) {
        // Remove all freed frames from FIFO queue (if present)
        for (int fid : freed) {
            fifo->frame_freed(fid);
        }
        // Reuse freed frames in LIFO order (as required)
        for (auto it = freed.rbegin(); it != freed.rend(); ++it) {
            free_list.push_front(*it);
        }
    }else if (auto* clock = dynamic_cast<Clock*>(pager.get())) {
        for (int fid : freed)
        free_list.push_back(fid);
    } 
    else if (auto* random = dynamic_cast<RandomPager*>(pager.get())) {
        for (int fid : freed)
        free_list.push_back(fid);
    } 
    else if (auto* aging = dynamic_cast<Aging*>(pager.get())) {
        for (auto it = freed.rbegin(); it != freed.rend(); ++it)
        free_list.push_front(*it);
    } 
    else {
        //Default
        for (int fid : freed)
            free_list.push_back(fid);
    }

    // reset page table entries
    for(int vp=0; vp<MAX_VPAGES; ++vp){
        proc.page_table[vp] = {};
    }
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
    } else if(algo == 'f') {
        pager = std::make_unique<FIFO>();
    } else if(algo == 'r' || algo == 'R') {
        pager = std::make_unique<RandomPager>();
    } else if(algo == 'c' || algo == 'C') {
        pager = std::make_unique<Clock>();
    } else if(algo == 'e' || algo == 'E') {
        pager = std::make_unique<NRU>();
    } else if(algo == 'a') {
        pager = std::make_unique<Aging>();
    } else if(algo == 'w') {
        pager = std::make_unique<WorkingSet>();
    } else {
        std::cerr << "error: pager algorithm '" << algo << "' is not implemented\n";
        return 1; // terminate instead of silently choosing another pager
    }

    load_rand_file(argv[optind+1]);

    /* 2. Decode debug flags in the -o string */
    bool dbg_x = opts.find('x') != std::string::npos;
    bool dbg_y = opts.find('y') != std::string::npos;
    bool dbg_f = opts.find('f') != std::string::npos;
    dbg_a_enabled = opts.find('a') != std::string::npos;

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
            if(pte.PRESENT){ 
                pte.REFERENCED=1; if(ins.op=='w'){
                if(pte.WRITE_PROTECT){ 
                    std::cout<<" SEGPROT\n"; 
                    cur.segprot++; total_cost+=COST_SEGPROT; 
                }
                else pte.MODIFIED=1; }
            } 
        }

        if(ins.op=='e'){
            int pid_to_exit = ins.arg;
            std::cout << "EXIT current process " << pid_to_exit << "\n"; // exact reference format
            process_exit(procs[pid_to_exit]);
            exit_cnt++; total_cost += COST_EXIT - 1; // already counted 1 cycle

            if(cur_pid == pid_to_exit) cur_pid = -1; // exiting currently running process
            continue;
        }

        if (dbg_x && cur_pid >= 0) dump_pt(cur);
        if(dbg_y) dump_all_pts(procs);
        if(dbg_f) dump_frame_table();
    }

    // ---- footer ----
    for(const auto& p:procs){ 
        dump_pt(p); 
    }
    dump_frame_table();
    for(const auto& p:procs){ 
        std::cout<<"PROC["<<p.pid<<"]: U="<<p.unmaps<<" M="<<p.maps
        <<" I="<<p.ins<<" O="<<p.outs<<" FI="<<p.fins<<" FO="<<p.fouts<<" Z="<<p.zeros
        <<" SV="<<p.segv<<" SP="<<p.segprot<<"\n"; 
    }
    std::cout<<"TOTALCOST "<<instr_cnt<<' '<<ctx_cnt<<' '<<exit_cnt<<' '<<total_cost<<' '<<sizeof(pte_t)<<"\n";

    return 0;
}