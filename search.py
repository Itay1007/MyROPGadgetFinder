import addresses
from infosec.core import assemble
from typing import Tuple, Iterable
import string


ASM_COMMANDS_SEPARETOR = ";"

GENERAL_REGISTERS = [
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'
]


ALL_REGISTERS = GENERAL_REGISTERS + [
    'esp', 'eip', 'ebp'
]


class GadgetSearch(object):
    def __init__(self, dump_path: str, start_addr=None):
        """
        Construct the GadgetSearch object.

        Input:
            dump_path: The path to the memory dump file created with GDB.
            start_addr: The starting memory address of this dump. Use
                        `addresses.LIBC_TEXT_START` by default.
        """
        self.start_addr = (start_addr if start_addr is not None
                           else addresses.LIBC_TEXT_START)
        with open(dump_path, 'rb') as f:
            self.dump = f.read()

    def get_format_count(self, gadget_format: str) -> int:
        """
        Get how many different register placeholders are in the pattern.

        Examples:
            self.get_format_count('POP ebx')
            => 0
            self.get_format_count('POP {0}')
            => 1
            self.get_format_count('XOR {0}, {0}; ADD {0}, {1}')
            => 2
        """
        # Hint: Use the string.Formatter().parse method:
        #
        #   import string
        #   print string.Formatter().parse(gadget_format)
        formats = []
        for token in string.Formatter().parse(gadget_format):
            if token[1] is not None and token[1] not in formats:
                formats.append(token[1])
        return len(formats)

    def get_register_combos(self, nregs: int, registers: Tuple[str]) -> Iterable[Iterable[str]]:
        """
        Return all the combinations of `registers` with `nregs` registers in
        each combination. Duplicates ARE allowed!

        Example:
            self.get_register_combos(2, ('eax', 'ebx'))
            => [['eax', 'eax'],
                ['eax', 'ebx'],
                ['ebx', 'eax'],
                ['ebx', 'ebx']]
        """
        combos = []
        registers_lst = list(registers)
        combos_num = len(registers_lst) ** nregs
        
        def base10_to_base(b: int, number: int) -> str:
            if number == 0:
                return "0"
            
            reverse_digits = []
            while number > 0:
                reverse_digits.append(number % b)
                number = number // b
            digits = reverse_digits[::-1]
            digits_str = ""

            for digit in digits:
                digits_str += str(digit)
            
            return digits_str
        
        for combo_idx in range(combos_num):
            indices_idx_str = base10_to_base(len(registers_lst), combo_idx).zfill(nregs)
            indices_idx_lst = [int(dig) for dig in indices_idx_str]
        
            combo = [registers[indice] for indice in indices_idx_lst]
            combos.append(combo)                

        return combos

    def format_all_gadgets(self, gadget_format: str, registers: Tuple[str]) -> Iterable[str]:
        """
        Format all the possible gadgets for this format with the given
        registers.

        Example:
            self.format_all_gadgets("POP {0}; ADD {0}, {1}", ('eax', 'ecx'))
            => ['POP eax; ADD eax, eax',
                'POP eax; ADD eax, ecx',
                'POP ecx; ADD ecx, eax',
                'POP ecx; ADD ecx, ecx']
        """
        # Hints:
        #
        # 0. Use the previous functions to count the number of placeholders,
        #    and get all combinations of registers.
        #
        # 1. Use the `format` function to build the string:
        #
        #    'Hi {0}! I am {1}, you are {0}'.format('Luke', 'Vader')
        #    => 'Hi Luke! I am Vader, you are Luke'
        #
        # 2. You can pass a list of arguments instead of specifying each
        #    argument individually. Use the internet, the force is strong with
        #    StackOverflow.

        formats_num = self.get_format_count(gadget_format)
        registers_combos = self.get_register_combos(formats_num, registers)
        all_gadgets = [gadget_format.format(*tuple(registers_combo)) for registers_combo in registers_combos]
        return all_gadgets

    def find_all(self, gadget: str) -> Iterable[int]:
        """
        Return all the addresses of the gadget inside the memory dump.

        Example:
            self.find_all('POP eax')
            => < all ABSOLUTE addresses in memory of 'POP eax; RET' >
        """
        # Notes:
        #
        # 1. Addresses are ABSOLUTE (for example, 0x08403214), NOT RELATIVE to
        #    the beginning of the file (for example, 12).
        #
        # 2. Don't forget to add the 'RET'.
        gadget_addresses = []
        full_gadget = gadget + ASM_COMMANDS_SEPARETOR + 'RET'
        full_gadget_bytes = assemble.assemble_data(full_gadget)
        full_gadget_lst = list(full_gadget_bytes)
        dump_lst = list(self.dump)
        
        for position in range(len(dump_lst)):
            if position + len(full_gadget_lst) - 1 >= len(dump_lst):
                break
            if full_gadget_lst == dump_lst[position:(position + len(full_gadget_lst))]:
                gadget_relative_addr = position
                gadget_absolute_addr = gadget_relative_addr + self.start_addr
                #gadget_absolute_addr_hex = hex(gadget_absolute_addr)
                gadget_addresses.append(gadget_absolute_addr)
        
        return gadget_addresses
            

    def find(self, gadget: str, condition=None) -> int:
        """
        Return the first result of find_all. If condition is specified, only
        consider addresses that meet the condition.
        """
        condition = condition or (lambda x: True)
        try:
            return next(addr for addr in self.find_all(gadget)
                        if condition(addr))
        except StopIteration:
            raise ValueError("Couldn't find matching address for " + gadget)

    def find_all_formats(self, gadget_format: str,
                         registers: Iterable[str] = GENERAL_REGISTERS) -> Iterable[Tuple[str, int]]:
        """
        Similar to find_all - but return all the addresses of all
        possible gadgets that can be created with this format and registers.
        Every element in the result will be a tuple of the gadget string and
        the address in which it appears.

        Example:
            self.find_all_formats('POP {0}; POP {1}')
            => [('POP eax; POP ebx', address1),
                ('POP ecx; POP esi', address2),
                ...]
        """
        all_gadgets_formats = []
        all_gadgets = self.format_all_gadgets(gadget_format, GENERAL_REGISTERS )
        for gadget in all_gadgets:
            gadget_addresses = self.find_all(gadget)
            
            for gadget_address in gadget_addresses:
                all_gadgets_formats.append(tuple([gadget, gadget_address]))
        return all_gadgets_formats

    def find_format(self, gadget_format: str,
                    registers: Iterable[str] = GENERAL_REGISTERS,
                    condition=None) -> Tuple[str, int]:
        """
        Return the first result of find_all_formats. If condition is specified,
        only consider gadget-address tuples that meet the condition.
        """
        condition = condition or (lambda x: True)
        try:
            return next(
                gadget_addr for gadget_addr in self.find_all_formats(gadget_format, registers)
                if condition(gadget_addr)
            )
        except StopIteration:
            raise ValueError(
                "Couldn't find matching address for " + gadget_format)
