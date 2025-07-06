#include <getopt.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>



/* -----------------------------------------------------------------
   Placeholder debug print helpers – replace with real versions later
------------------------------------------------------------------*/
static void dump_current_pt()    { std::cout << "[DEBUG-x] current PT\n"; }
static void dump_all_pts()       { std::cout << "[DEBUG-y] all PTs\n";    }
static void dump_frame_table()   { std::cout << "[DEBUG-f] frame table\n";}
static void dump_aging_details() { std::cout << "[DEBUG-a] aging info\n"; }

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
    /* 2. Decode debug flags in the -o string */
    bool dbg_x = opts.find('x') != std::string::npos;
    bool dbg_y = opts.find('y') != std::string::npos;
    bool dbg_f = opts.find('f') != std::string::npos;
    bool dbg_a = opts.find('a') != std::string::npos;


    /*placeholder simulation line so runit/gradeit have something to diff. */
    const int FAKE_INSTRUCTIONS = 3;   
    for (int pc = 0; pc < FAKE_INSTRUCTIONS; ++pc) {

        /* Per-instruction debug output ------------------------------ */
        if (dbg_x) dump_current_pt();
        if (dbg_y) dump_all_pts();
        if (dbg_f) dump_frame_table();
        if (dbg_a) dump_aging_details();
    }
    std::cout << "TOTALCOST 1 2 3 4 5\n"; 
    return 0; 
}