# utils/logger.py

from colorama import Fore, Style, init

init(autoreset=True)


def info(msg):
    print(Fore.CYAN + "[INFO] " + msg + Style.RESET_ALL)


def success(msg):
    print(Fore.GREEN + "[OK] " + msg + Style.RESET_ALL)


def warning(msg):
    print(Fore.YELLOW + "[WARN] " + msg + Style.RESET_ALL)


def error(msg):
    print(Fore.RED + "[ERROR] " + msg + Style.RESET_ALL)