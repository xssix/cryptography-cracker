import os
import sys
import base64
import hashlib
import binascii
import itertools
import string
import time
import multiprocessing
from multiprocessing import Pool, cpu_count, Value

try:
    from Cryptodomex.Cipher import AES
    from Cryptodomex.Util.Padding import unpad
except ImportError:
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import unpad
    except ImportError:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.align import Align
from rich.prompt import Prompt, IntPrompt
from rich.columns import Columns
from rich import box

console = Console()

BANNER_ASCII = """
[bold cyan]

██╗░░██╗░██████╗░██████╗  ░█████╗░██████╗░░█████╗░░█████╗░██╗░░██╗███████╗██████╗░
╚██╗██╔╝██╔════╝██╔════╝  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║░██╔╝██╔════╝██╔══██╗
░╚███╔╝░╚█████╗░╚█████╗░  ██║░░╚═╝██████╔╝███████║██║░░╚═╝█████═╝░█████╗░░██████╔╝
░██╔██╗░░╚═══██╗░╚═══██╗  ██║░░██╗██╔══██╗██╔══██║██║░░██╗██╔═██╗░██╔══╝░░██╔══██╗
██╔╝╚██╗██████╔╝██████╔╝  ╚█████╔╝██║░░██║██║░░██║╚█████╔╝██║░╚██╗███████╗██║░░██║
╚═╝░░╚═╝╚═════╝░╚═════╝░  ░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝ [/bold cyan][bold blue]by xss v1.0.0[/bold blue]
"""

shared_counter = Value('Q', 0)
shared_found = Value('b', 0)
shared_pwd = multiprocessing.Array('c', 128)
shared_text = multiprocessing.Array('c', 1024)
shared_mode = multiprocessing.Array('c', 64)

def is_printable(data):
    if not data: return False
    printable = set(string.printable.encode())
    printable_count = sum(1 for b in data if b in printable)
    return (printable_count / len(data)) > 0.95

def worker_init(c, f, p, t, m):
    global counter, found, out_pwd, out_text, out_mode
    counter = c
    found = f
    out_pwd = p
    out_text = t
    out_mode = m

def core_worker(args):
    combos, ciphertext, mode, iv, klen, mname = args
    _sha256 = hashlib.sha256
    _AES_new = AES.new
    _unpad = unpad
    
    local_count = 0
    for pwd in combos:
        if found.value: return
        
        try:
            key = _sha256(pwd.encode()).digest()[:klen]
            if mode in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
                cipher = _AES_new(key, mode, iv=iv)
            elif mode == AES.MODE_CTR:
                from Cryptodomex.Util import Counter
                ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
                cipher = _AES_new(key, mode, counter=ctr)
            else: # ECB
                cipher = _AES_new(key, mode)
                
            dec = cipher.decrypt(ciphertext)
            
            if mode in [AES.MODE_CBC, AES.MODE_ECB]:
                res = _unpad(dec, 16)
            else:
                res = dec

            if res and is_printable(res):
                with found.get_lock():
                    if found.value: return
                    found.value = 1
                    out_pwd.value = pwd.encode()
                    out_text.value = res[:1023]
                    out_mode.value = f"AES-{klen*8} {mname}".encode()
                return
        except:
            pass
        
        local_count += 1
        if local_count >= 10000:
            with counter.get_lock():
                counter.value += local_count
            local_count = 0
    with counter.get_lock():
        counter.value += local_count

class AESCracker:
    def __init__(self):
        self.num_cores = cpu_count()
        self.raw_data = None
        self.target_hex = ""

    def render_ui(self, speed, elapsed, phase):
        header = Panel(
            Align.center(Group(
                Text.from_markup(BANNER_ASCII),
                Text("Attemptiong to crack", style="dim cyan")
            )),
            box=box.HORIZONTALS, border_style="bold blue"
        )

        stats = Table.grid(padding=(0, 2))
        stats.add_column(style="bold blue", width=15)
        stats.add_column(style="bright_white")
        stats.add_row("STATUS", "[bold green]RUNNING[/bold green]")
        stats.add_row("CORES", f"{self.num_cores}")
        stats.add_row("SCANNED", f"{shared_counter.value:,.0f}")
        stats.add_row("SPEED", f"{speed:,.0f} H/s")
        stats.add_row("TIME", f"{elapsed:.1f}s")
        
        stats_panel = Panel(stats, title="[ STATS ]", border_style="blue", expand=True)

        info = Panel(
            Group(
                Text.assemble(("DATA:   ", "bold blue"), (f"{self.target_hex[:45]}...", "cyan")),
                Text.assemble(("\nCURRENT: ", "bold blue"), (f"{phase}", "bold white")),
                Text.assemble(("\nMODULE:  ", "bold blue"), ("Cryptography", "dim"))
            ),
            title="[ TARGET ]", border_style="cyan", expand=True
        )

        pulse_len = 30
        pulse_pos = int(time.time() * 10) % (pulse_len * 2)
        if pulse_pos > pulse_len: pulse_pos = pulse_len * 2 - pulse_pos
        pulse_bar = [" "] * pulse_len
        if pulse_pos < pulse_len: pulse_bar[pulse_pos] = "█"
        pulse_str = "".join(pulse_bar)

        progress = Panel(
            Align.center(f"[bold blue]<<<[/bold blue] [cyan]{pulse_str}[/cyan] [bold blue]>>>[/bold blue]"),
            title="[ SCAN ]", border_style="blue"
        )

        return Group(header, Columns([stats_panel, info]), progress)

    def startup(self):
        console.clear()
        console.print(Align.center(Text.from_markup(BANNER_ASCII)))
        
        modes_menu = Table.grid(padding=(0, 1))
        modes_menu.add_column(style="bold cyan")
        modes_menu.add_column(style="white")
        modes_menu.add_row("0", "Try All Modes (Recommended)")
        modes_menu.add_row("1", "AES-CBC")
        modes_menu.add_row("2", "AES-ECB")
        modes_menu.add_row("3", "AES-CFB")
        modes_menu.add_row("4", "AES-OFB")
        modes_menu.add_row("5", "AES-CTR")
        
        console.print(Panel(modes_menu, title="[ MODE SELECT ]", border_style="blue"))
        mode_choice = IntPrompt.ask("\n[bold blue]Select Mode[/bold blue]", default=0)
        
        raw_inp = Prompt.ask("[bold blue]Paste String[/bold blue]").strip()
        try:
            if all(c in string.hexdigits for c in raw_inp):
                self.raw_data = binascii.unhexlify(raw_inp)
            else:
                self.raw_data = base64.b64decode(raw_inp)
            self.target_hex = raw_inp
        except:
            console.print("[bold red]Error decoding string![/bold red]")
            return

        depth = IntPrompt.ask("[bold blue]Max Length[/bold blue]", default=4)
        
        console.clear()
        
        all_configs = {
            1: (AES.MODE_CBC, "CBC"),
            2: (AES.MODE_ECB, "ECB"),
            3: (AES.MODE_CFB, "CFB"),
            4: (AES.MODE_OFB, "OFB"),
            5: (AES.MODE_CTR, "CTR"),
        }
        
        selected_modes = []
        if mode_choice == 0:
            selected_modes = list(all_configs.values())
        elif mode_choice in all_configs:
            selected_modes = [all_configs[mode_choice]]
        else:
            selected_modes = list(all_configs.values())

        configs = []
        for klen in [32, 16]: # 256, 128
            for m_enum, m_name in selected_modes:
                if m_enum == AES.MODE_ECB:
                    configs.append((m_enum, self.raw_data, None, klen, m_name))
                elif len(self.raw_data) > 16:
                    configs.append((m_enum, self.raw_data[16:], self.raw_data[:16], klen, m_name))

        charset = string.ascii_letters + string.digits
        start_t = time.time()
        
        with Live(auto_refresh=False) as live:
            with Pool(processes=self.num_cores, initializer=worker_init, 
                      initargs=(shared_counter, shared_found, shared_pwd, shared_text, shared_mode)) as pool:
                
                for length in range(1, depth + 1):
                    if shared_found.value: break
                    
                    combos = ["".join(c) for c in itertools.product(charset, repeat=length)]
                    batch_size = max(1, len(combos) // (self.num_cores * 4))
                    chunks = [combos[i:i + batch_size] for i in range(0, len(combos), batch_size)]
                    
                    for m_enum, ct, iv, klen, mname in configs:
                        if shared_found.value: break
                        
                        phase = f"Len {length} | {mname}-{klen*8}"
                        worker_args = [(chk, ct, m_enum, iv, klen, mname) for chk in chunks]
                        
                        res = pool.map_async(core_worker, worker_args)
                        
                        while not res.ready():
                            if shared_found.value: break
                            elapsed = time.time() - start_t
                            speed = shared_counter.value / elapsed if elapsed > 0 else 0
                            live.update(self.render_ui(speed, elapsed, phase))
                            live.refresh()
                            time.sleep(0.05)

        if shared_found.value:
            console.print()
            try:
                decrypted_str = shared_text.value.decode('utf-8', errors='replace')
            except:
                decrypted_str = "[Binary]"

            console.print(Panel(
                Align.center(
                    Group(
                        Text("🔓 SUCCESS!", style="bold green", justify="center"),
                        Text("\n"),
                        Table.grid(padding=(0, 2)),
                        Text.assemble(("KEY:     ", "bold blue"), (f"{shared_pwd.value.decode()}\n", "bold bright_white")),
                        Text.assemble(("RESULT:  ", "bold blue"), (f"{decrypted_str}\n", "bold green")),
                        Text.assemble(("MODE:    ", "bold blue"), (f"{shared_mode.value.decode()}", "dim"))
                    )
                ),
                title="[ FOUND ]", border_style="green", box=box.DOUBLE, padding=(1, 4)
            ))
        else:
            console.print(Panel(Align.center("[bold red]NOT FOUND[/bold red]"), border_style="red"))

if __name__ == "__main__":
    multiprocessing.freeze_support()
    try:
        AESCracker().startup()
    except KeyboardInterrupt:
        console.print("\n[bold blue]Exiting...[/bold blue]")
