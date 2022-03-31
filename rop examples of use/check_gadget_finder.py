import search

LIBC_DUMP_PATH = './libc.bin'


def main():
    name = "mordecai"
    rop_engine = search.GadgetSearch(LIBC_DUMP_PATH)
    #print(rop_engine.get_register_combos(2, ('eax', 'ebx')))
    #print(rop_engine.get_register_combos(3, ('eax', 'ebx', 'ecx')))
    #print(rop_engine.format_all_gadgets("POP {0}; ADD {0}, {1}", ('eax', 'ecx')))
    #print(rop_engine.find_all('POP eax'))
    print(rop_engine.find_all_formats('POP {0}; POP {1}'))


if __name__ == "__main__":
    main()
