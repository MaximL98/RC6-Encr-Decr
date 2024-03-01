class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_fails(*values):
    print(bcolors.FAIL+ " ".join(map(str,values))+bcolors.ENDC)

def print_success(*values):
    print(bcolors.OKGREEN+ " ".join(map(str,values))+bcolors.ENDC)


def get_user_info():
    print("Welcome To Our Payment secution")
    first_name = input("Enter first name: ")
    last_name = input("Enter last name: ")
    card_number = input("Enter card number: ")
    return first_name, last_name, card_number

def get_cred(first_name, last_name):
    print(f"Hello {last_name} {first_name} ")
    passcode = input("Enter passcode (4 numbers): ")
    cvc = input("Enter cvc (3 numbers): ")
    data = input("Enter exp card date (m/y): ")
    return passcode, cvc, data