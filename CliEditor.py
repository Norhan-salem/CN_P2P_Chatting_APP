"""
    ## Extending Eran Ulas' Chatting Application
    ## Team 24
"""

from colorama import Fore, Style, init
from pyfiglet import Figlet
from rich import print
import re

def activate_link(messageReceived):
    # Regular expression to match URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, messageReceived)

    # Replace each URL with a markdown link
    for url in urls:
        message = messageReceived.replace(url, f'{url}')

    return messageReceived


def format_message(messageReceived):
    if messageReceived.endswith("/B"):
        # Remove the last two characters "/B" and make the messageReceived bold
        print("[bold]" + messageReceived[:-2] + "[/bold]")
    elif messageReceived.endswith("/I"):
        # Remove the last two characters "/I" and make the messageReceived italic
        print("[italic]" + messageReceived[:-2] + "[/italic]")
    else:
        # If the messageReceived doesn't end with "/B" or "/I", print it as is
        print(messageReceived)


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


def yellow_message_without_space(message, color=Fore.LIGHTYELLOW_EX, style=Style.RESET_ALL):
    return f"{style}{color}{message}{Style.RESET_ALL}"


def red_message_without_space(message, color=Fore.LIGHTRED_EX, style=Style.RESET_ALL):
    return f"{style}{color}{message}{Style.RESET_ALL}"


def blue_message_without_space(message, color=Fore.LIGHTBLUE_EX, style=Style.RESET_ALL):
    return f"{style}{color}{message}{Style.RESET_ALL}"
