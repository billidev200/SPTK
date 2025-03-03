# Main Menu 
def main():
    print("Spartiatis Toolkit")
    print("1. Port Scanner")
    print("6. Exit")

    choice = input("Select an option: ")

    if choice == '1':
        target = input("Enter target IP: ")
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
        ports = range(start_port, end_port+1)
    elif choice == '6':
        exit()

    else:
        print("Invalid option")

if __name__ == "__main__":
    main()