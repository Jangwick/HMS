from app import create_app, db
from models.registry import model_registry
from utils.ip_lockout import clear_all_lockouts, clear_ip_lockout, get_all_locked_ips

app = create_app()

def show_locked_ips():
    """Display all currently locked IPs."""
    locked_ips = get_all_locked_ips()
    if locked_ips:
        print(f"\nCurrently locked IPs ({len(locked_ips)}):")
        for ip, info in locked_ips.items():
            print(f"  - {ip}: {info['attempts']} attempts, locked until {info['locked_until']}")
    else:
        print("\nNo IPs are currently locked.")

def unlock_all_ips():
    """Clear all IP lockouts."""
    count = clear_all_lockouts()
    print(f"\nCleared {count} IP lockout(s).")

def unlock_specific_ip(ip_address):
    """Clear lockout for a specific IP."""
    if clear_ip_lockout(ip_address):
        print(f"\nUnlocked IP: {ip_address}")
    else:
        print(f"\nIP {ip_address} was not locked.")

def main():
    print("=" * 50)
    print("IP Lockout Management Tool")
    print("=" * 50)
    print("\nOptions:")
    print("  1. Show all locked IPs")
    print("  2. Unlock all IPs")
    print("  3. Unlock specific IP")
    print("  4. Exit")
    
    while True:
        choice = input("\nEnter choice (1-4): ").strip()
        
        if choice == '1':
            show_locked_ips()
        elif choice == '2':
            confirm = input("Are you sure you want to unlock ALL IPs? (y/n): ").strip().lower()
            if confirm == 'y':
                unlock_all_ips()
            else:
                print("Cancelled.")
        elif choice == '3':
            ip = input("Enter IP address to unlock: ").strip()
            if ip:
                unlock_specific_ip(ip)
            else:
                print("No IP address entered.")
        elif choice == '4':
            print("\nGoodbye!")
            break
        else:
            print("Invalid choice. Please enter 1-4.")

if __name__ == '__main__':
    main()
