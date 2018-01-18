def initLDSC():
    # analyse loader_t structure
    strudef_loader_t = "            \
        typedef struct loader_t     \
        {                           \
            unsigned int version;   \
            unsigned int flags;     \
            int (__stdcall* accept_file)(void* li, char* filefn, int n);        \
            void (__stdcall* load_file)(void* li, int neflags, char* filefn);   \
            int (__stdcall* save_file)(FILE* fp, char* filefn);                 \
            int (__stdcall* move_segm)(unsigned int from, unsigned int to, size_t size, char* filefn);\
            void* unused;           \
        } _loader_t;"        
    SetLocalType(-1, strudef_loader_t, 0)
    SetType(0, "loader_t")
    
    LDSC = LocByName("_LDSC")
    SetType(LDSC, "loader_t")    

    
if __name__ == "__main__":
    if LocByName("_LDSC") < 0xFFFFFFFF:
        initLDSC()
