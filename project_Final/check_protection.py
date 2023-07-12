import os
import subprocess
import re
from pwn import *
import glob


#context.log_level = 'debug'

class StackVisualizer:
    def __init__(self, is_64bit):
        self.stack = []
        self.is_64bit = is_64bit

    def push(self, data):
        self.stack.append(data)

    def draw_stack_structure(self):
        print("High Memory Addresses")
        print("+" + "-" * 45 + "+")
        for item in reversed(self.stack):
            print(f"| {item['name'].ljust(20)} | Offset: {str(item['offset']).ljust(20)} |")
            print("+" + "-" * 45 + "+")
        print("Low Memory Addresses")


def objdump_disassemble(binary):
    cmd = f"objdump -d -M intel {binary}"
    output = subprocess.check_output(cmd, shell=True).decode("utf-8")
    return output.split(os.linesep)

def parse_assembly(assembly, stack_visualizer, target_function, is_64bit, has_canary):
    push_pattern = re.compile(r"\spush\s")
    sub_pattern = re.compile(r"\ssub\s")
    ret_pattern = re.compile(r"\sret\s")
    input_func_pattern = re.compile(r"\s(gets|fgets|scanf|read|recv)\s")
    mov_pattern = re.compile(r"\smov\s")
    call_pattern = re.compile(r"\scall\s")

    in_target_function = False
    offset = 0
    last_mov_hex = None
    input_function_offset = None
    ret_offset = None
    another_func_after_input = False

    base_ptr = "ebp" if not is_64bit else "rbp"

    local_var_counter = {}
    base_offset = 4 if not is_64bit else 8 # Initialize base offset for local variables

    for line in assembly:
        if f'<{target_function}>:' in line:
            in_target_function = True
        elif in_target_function and line.strip() == '':
            break
        elif in_target_function:
            if push_pattern.search(line):
                operand = line.split("push")[-1].strip()
                if is_64bit:
                    stack_visualizer.push({'name': operand[:8], 'offset': offset})
                    offset += 8
                else:
                    stack_visualizer.push({'name': operand, 'offset': offset})
                    offset += 4
            elif sub_pattern.search(line):
                operand = line.split("sub")[-1].strip()
                if "," in operand:
                    _, size = operand.split(",")
                    size = int(size.strip(), 16)
                    if is_64bit:
                        for i in range(size // 8): # Assuming 64-bit, each variable occupies 8 bytes
                            if i not in local_var_counter:
                                local_var_counter[i] = 0
                            else:
                                local_var_counter[i] += 1
                            stack_visualizer.push({'name': f"Local var {i}.{local_var_counter[i]} <- {base_ptr} - {hex(base_offset)}", 'offset': offset})
                            offset += 8
                            base_offset += 8
                    else:
                        for i in range(size // 4): # Assuming 32-bit, each variable occupies 4 bytes
                            if i not in local_var_counter:
                                local_var_counter[i] = 0
                            else:
                                local_var_counter[i] += 1
                            stack_visualizer.push({'name': f"Local var {i}.{local_var_counter[i]} <- {base_ptr} - {hex(base_offset)}", 'offset': offset})
                            offset += 4
                            base_offset += 4
            elif ret_pattern.search(line):
                if has_canary:
                    stack_visualizer.push({'name': "Stack Canary", 'offset': offset})
                    offset += 4 if not is_64bit else 8
                stack_visualizer.push({'name': "RET", 'offset': offset})
                offset += 4 if not is_64bit else 8
                if input_function_offset is not None and ret_offset is None:
                    ret_offset = offset
                    print('RET found at offset:', ret_offset)
                    print('Offset from input function to RET:', ret_offset - input_function_offset)
            elif input_func_pattern.search(line):
                print('Input function called at offset:', offset)
                stack_visualizer.push({'name': "<Your input in here ! >", 'offset': offset})
                input_function_offset = offset
            elif call_pattern.search(line):
                if input_function_offset is not None and ret_offset is None:
                    print("Warning: Another function is called after the user input function but before RET.")
                if "0x" in line.split("call")[-1]:
                    last_mov_hex = line.split("call")[-1].strip()
            elif mov_pattern.search(line):
                mov_parts = line.split("mov")[-1].strip().split(",")
                if "0x" in mov_parts[1]:
                    last_mov_hex = mov_parts[1].strip()
            elif call_pattern.search(line) and last_mov_hex is not None:
                stack_visualizer.push({'name': f"Function Argument: {last_mov_hex}", 'offset': offset})
                offset += 4 if not is_64bit else 8
                last_mov_hex = None # Reset the last mov hex number






def is_canary_protected(assembly):
    for line in assembly:
        if "__stack_chk_fail" in line:
            return True
    return False


def is_64bit_binary(binary_path):
    output = subprocess.check_output(f"file {binary_path}", shell=True).decode("utf-8")
    return "64-bit" in output

def find_offset(binary_path, is_incremental):
    # If we are not incrementally increasing the pattern length, just use a fixed size.
    pattern_len = 1 if is_incremental else 1024
    max_pattern_len = 1024  # Set some maximum limit to prevent infinite loop

    offset = -1
    while pattern_len <= max_pattern_len:
        pattern = cyclic(pattern_len)

        # automatically detect architecture and set context
        context.binary = binary_path
        p = process(binary_path)
        p.sendline(pattern)
        p.wait()

        core_files = glob.glob('core*')
        if not core_files:
            if is_incremental:
                print(f"No crash with pattern length {pattern_len}. Increasing the pattern length...")
                pattern_len += 1
            else:
                print("No core dump file was found.")
                break
        else:
            core_file = sorted(core_files, key=os.path.getctime)[-1]

            cmd = f"gdb -q -ex 'file {binary_path}' -ex 'core-file {core_file}' -ex 'info frame' -ex 'quit'"
            output = subprocess.check_output(cmd, shell=True).decode("utf-8")

            for line in output.split('\n'):
                if "eip" in line or "rip" in line:
                    address = int(line.split()[-1], 16)
                    break

            if context.arch == 'i386':  # 32-bit
                for i in range(4):
                    try:
                        offset = cyclic_find(p32(address & (0xffffffff << (i*8))))
                        break
                    except ValueError:
                        pass
            elif context.arch == 'amd64':  # 64-bit
                for i in range(8):
                    try:
                        offset = cyclic_find(p64(address & (0xffffffffffffffff << (i*8))))
                        break
                    except ValueError:
                        pass

            if offset != -1:
                print(f"Crash occurred with pattern length {pattern_len}. Offset found: {offset}")
                break
            else:
                if is_incremental:
                    print(f"No offset found with pattern length {pattern_len}. Increasing the pattern length...")
                    pattern_len += 1
                else:
                    print("The value from the eip/rip register is not part of the cyclic pattern.")
                    break

    if pattern_len > max_pattern_len:
        print("Exceeded maximum pattern length without finding offset.")
        
    return offset
def check_for_second_input_func(assembly):
    input_funcs = ["gets", "read"]
    input_funcs_count = 0
    for line in assembly:
        if any(func in line for func in input_funcs):
            input_funcs_count += 1
            if input_funcs_count > 1:
                return True
    return False


def main(binary_path):
    print("바이너리를 분석 중입니다...")
    assembly_output = objdump_disassemble(binary_path)

    target_function = "main"
    is_64bit = is_64bit_binary(binary_path)

    print("카나리 보호 여부를 확인 중입니다...")
    has_canary = is_canary_protected(assembly_output)
    print("카나리 보호 존재 여부:", has_canary)

    stack_visualizer = StackVisualizer(is_64bit)

    print(f"어셈블리 분석 중 ({'64-bit' if is_64bit else '32-bit'})...")
    parse_assembly(assembly_output, stack_visualizer, target_function, is_64bit, has_canary)

    print("스택 구조를 그리는 중입니다...")
    stack_visualizer.draw_stack_structure()

    another_func_after_input = check_for_second_input_func(assembly_output)
    if not another_func_after_input and not has_canary: 
        print("오프셋을 찾고 있습니다. 이 과정은 시간이 소요될 수 있습니다...")
        offset = find_offset(binary_path, is_incremental=True)
    else:
        print("오프셋을 찾는 중...")
        offset = find_offset(binary_path, is_incremental=False)

    core_files = glob.glob('core*')
    for core_file_path in core_files:
        try:
            os.remove(core_file_path)
            print(f"코어 파일 {core_file_path}를 삭제했습니다.")
        except Exception as e:
            print("코어 파일을 삭제하지 못했습니다. 에러:", str(e))

    return offset



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("사용법: python stack_visualizer.py [binary_path]")
        sys.exit(1)

    
    binary_path = sys.argv[1]
    offset = main(binary_path)
    

