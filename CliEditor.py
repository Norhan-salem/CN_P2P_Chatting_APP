import threading
from colorama import Fore, Style, init
from pyfiglet import Figlet

# Initialize colorama
init()


def title(text):
    fig = Figlet(font='starwars', width=200)
    styled_text = f"{Fore.LIGHTWHITE_EX}{Style.BRIGHT}{fig.renderText(text)}{Style.RESET_ALL}"
    print(styled_text)


def green_message(message, color=Fore.LIGHTGREEN_EX, style=Style.RESET_ALL):
    print(f"{style}{color}{message}{Style.RESET_ALL}", end='\n')


def red_message(message, color=Fore.LIGHTRED_EX, style=Style.RESET_ALL):
    print(f"{style}{color}{message}{Style.RESET_ALL}", end='\n')


def green_message_ok(message, color=Fore.LIGHTGREEN_EX, style=Style.RESET_ALL):
    print(f"{style}{color}{message}{Style.RESET_ALL}")


def red_message_reject(message, color=Fore.LIGHTRED_EX, style=Style.RESET_ALL):
    print(f"{style}{color}{message}{Style.RESET_ALL}")


def yellow_message(message, color=Fore.LIGHTYELLOW_EX, style=Style.RESET_ALL):
    print(f"{style}{color}{message}{Style.RESET_ALL}", end='\n')


def blue_message(message, color=Fore.LIGHTBLUE_EX, style=Style.RESET_ALL):
    print(f"{style}{color}{message}{Style.RESET_ALL}", end='\n')

def green_message_without_space(message, color=Fore.LIGHTGREEN_EX, style=Style.RESET_ALL):
    return f"{style}{color}{message}{Style.RESET_ALL}"