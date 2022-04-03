from infosec.core import assemble
from search import GadgetSearch
import os.path

LIBC_DUMP_PATH = './libc.bin'

def parse(search, command):
    try:
        print(search.find_format(command))
        optional_more_output = input("Want to see all findings? Type 'accept' if you do\n>> ")
        if optional_more_output == "accept":
            print(search.find_all_formats(command))
    except Exception as e:
        print(e)

def main():
    print("------Welcome to Itay Barok ROP Gadget Search Application!------")
    print("[based on my own ROP gadget search which supports intel 32bits commands]")
    print("[!] Write assembly commands like: mov eax, eax")
    print("[!] and get to find their position in your binary file")
    while True:
        filePath = input("Enter path to your binary file ['enter' for default ./libc.bin]\n>> ")
        if filePath == "":
            filePath = LIBC_DUMP_PATH
        if not os.path.exists(filePath):
            print("Not such file")
            continue
        search = GadgetSearch(filePath)
        break
    while True:
        print("Manual: ")
        print("[+] intel 32 assembly command or")
        print("[+] 'exit' to finish cleanly or")
        print("[+] 'user guide' to read about the advanced search queries!")
        command = input(">> ")
        if command == 'exit':
            print("Hope my application helped you exploit your way into :-) ")
            return 0
        if command == 'user guide':
            user_guide()
            continue
        parse(search, command)


def user_guide():
    print("Welcome! This is my user guide")
    print("Basics first:")
    print("[1] mov eax, eax")
    print("[2] push esp")
    print("[3] --- write your own example ---")
    print("Multi commands sequence:")
    print("[1] push eax; pop ebx")
    print("dec; dec; dec; dec")
    print("xor eax, eax; mov ebx, 0; and ecx, 0; push 0; pop edx")
    print("To the advanced part!")
    print("Format search: ")
    print("[1] mov {0}, {0} ; {0} and {1} are the same registers")
    print("[2] mov {0}, {1} ; {0} and {1} be from different registers")
    print("[3] pop {0}")
    print("[4] --- write your own example ---", end="\n\n")


if __name__ == "__main__":
    main()
