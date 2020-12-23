#Ramon van Ek - 1743711

#Default values
input_file = "router.log"
output_file = "out.txt"


# Read the config file
try:
    ini_file = open( "config.ini", "r" )

    for line in ini_file:
        line = line.replace( "\n", "" )
        option, value = line.split( "=" )

        if option == "input_file":
            input_file = value
        elif option == "output_file":
            output_file = value
        else:
            print( "Warning: Unknown configuration line, accepted options are 'input_file' and 'output_file'" )

    ini_file.close()

except OSError:
    print( "Warning: File 'config.ini' could not be read, using default values")


def RE_open_source_file():
    try:
        log_file = open( input_file, "r")
        return log_file
    except OSError:
        print( "Error: Could not open source file" )
        exit(1)


def RE_number_of_refused_icmp_packets( writing = False ):
    # Open log file
    log_file = RE_open_source_file()

    # Create Basic Variables
    packets_refused = dict()
    total_packets = 0

    for text in log_file:
        if "%SEC-6-IPACCESSLOGDP" in text:
            # Get the message
            message = text.split( ":" )[4]

            # Split at the arrow
            before_arrow_stuff, after_arrow_stuff = message.split("->")

            # Find source ip, destination ip and packet amount
            source_ip = before_arrow_stuff.split( " " )[5]
            dest_ip_adress, packets = after_arrow_stuff.split(" (0/0), ")
            dest_ip_adress = dest_ip_adress[1:] # Remove Space
            packet_amount = packets.split( " " )[0] # Remove unnecessary text

            # Add the information to the dictionary
            if dest_ip_adress in packets_refused:
                packets_refused[source_ip] = packets_refused[source_ip] + int( packet_amount )
            else:
                packets_refused[source_ip] = int( packet_amount )

            # Count total packets
            total_packets = total_packets + int( packet_amount )

    print( "Er zijn: " + str( total_packets ) + " geweigerde packets" )

    # Close log file
    log_file.close()

    # Check whether we are writing
    if not writing:
        RE_print_RE_menu(RE_number_of_refused_icmp_packets)


def RE_top_status_changes( writing = False ):
    # Open log file
    log_file = RE_open_source_file()

    # Create Basic Variables
    status_changed = dict()

    for text in log_file:
        if "%LINK-3-UPDOWN" in text:
            # Get the message
            message = text.split( ":" )[4]

            # Get the information of the interface and the status message
            interface, status_message = message.split(",")
            interface = interface[1:] # Remove starting space

            # Changes the counts of ups and downs within the dictionary
            if interface in status_changed:
                if "up" in status_message:
                    status_changed[interface] = [ status_changed[interface][0] + 1, status_changed[interface][1] ]
                else:
                    status_changed[interface] = [ status_changed[interface][0], status_changed[interface][1] + 1 ]
            # Create a dictionary entry if not exists
            else:
                if "up" in status_message:
                    status_changed[interface] = [ 1, 0 ]
                else:
                    status_changed[interface] = [ 0, 1 ]

    # Sort the dictionary from high to low
    sorted_interfaces = sorted( status_changed.items(), key=lambda changes: changes[1], reverse=True)

    # Create a counter to stop after five iterations
    count = 0

    # Print the top 5
    for interface in sorted_interfaces:
        if ( count < 5 ):
            print('{} is {} keer up en {} keer down gegaan'.format(interface[0], interface[1][0], interface[1][1]))
            count = count + 1
        else:
            break

    # Close log file
    log_file.close()

    # Check whether we are writing
    if not writing:
        RE_print_RE_menu( RE_top_status_changes )


def RE_top_tcp_denied( writing = False ):
    # Open log file
    log_file = RE_open_source_file()

    # Create Basic Variables
    tcp_denied = dict()

    for text in log_file:
        if "%SEC-6-IPACCESSLOGP" in text:
            # Get the message
            message = text.split( ":" )[4]

            if "denied" in message and "tcp" in message:
                # Remove (0)
                message = message.replace("(0)", "")

                # Split at the arrow
                before_arrow_stuff, after_arrow_stuff = message.split("->")

                # Find source ip, destination ip and packet amount
                source_ip = before_arrow_stuff.split(" ")[5]
                dest_ip_adress, packets = after_arrow_stuff.split(", ")
                dest_ip_adress = dest_ip_adress[1:]  # Remove Space
                packet_amount = packets.split(" ")[0]  # Remove unnecessary text

                # Add the information to the dictionary
                if dest_ip_adress in tcp_denied:
                    tcp_denied[source_ip] = tcp_denied[source_ip] + int(packet_amount)
                else:
                    tcp_denied[source_ip] = int(packet_amount)

    # Sort the dictionary from high to low
    sorted_denials = sorted( tcp_denied.items(), key=lambda changes: changes[1], reverse=True)

    # Create a counter to stop after five iterations
    count = 0

    # Print the top 5
    for ip_address in sorted_denials:
        if ( count < 20 ):
            print('{} is geweigerd voor {} packets'.format(ip_address[0], ip_address[1]))
            count = count + 1
        else:
            break

    # Close log file
    log_file.close()

    # Check whether we are writing
    if not writing:
        RE_print_RE_menu( RE_top_tcp_denied )


def RE_vlan_errors( writing = False ):
    # Open log file
    log_file = RE_open_source_file()

    # Create Basic Variables
    vlan_error_list = dict()

    for text in log_file:
        if "%SPANTREE-2-BLOCK_PVID_LOCAL" in text:
            # Get the message
            message = text.split( ":" )[4]

            # Get the VLAN number
            vlan_number = message.split(" ")[4]
            vlan_number = vlan_number.replace( ".", "" )

            # Changes the counts of ups and downs within the dictionary
            if vlan_number in vlan_error_list:
                vlan_error_list[vlan_number] = vlan_error_list[vlan_number] + 1
            # Create a dictionary entry if not exists
            else:
                vlan_error_list[vlan_number] = 1

    # Sort the dictionary from high to low
    sorted_errors = sorted( vlan_error_list.items(), key=lambda changes: changes[1], reverse=True)

    # Print the top 5
    for vlan in sorted_errors:
        print('{} heeft {} foutmeldingen gegeven'.format(vlan[0], vlan[1]))

    # Close log file
    log_file.close()

    # Check whether we are writing
    if not writing:
        RE_print_RE_menu( RE_vlan_errors )


def RE_write_to_file( function ):
    import sys
    orginal_output = sys.stdout
    error = False

    try:
        out_std = open(output_file, "w")
        sys.stdout = out_std

        # perfom function
        function( True )

        sys.stdout = orginal_output
        out_std.close()
        print("De output is succesvol opgeslagen")

    except OSError:
        print( "Error: The output file could not be opened" )
        error = True

    finally:
        sys.stdout = orginal_output

        if error:
            exit( 1 )
    RE_menu()

def RE_manual():
    #Display manual
    print("")
    print("")
    print( "Input file: " + input_file)
    print( "Output file: " + output_file)
    print("Dit kan worden aangepast in 'config.ini'")
    print("")
    print("")
    RE_menu()

def RE_print_RE_menu( function ):
    # RE_menu in the function
    print("")
    print("")
    print("Kies 1 om terug te gaan naar het RE_menu.")
    print("Kies 2 om de output op te slaan")
    choice = input("Maak hieronder de keuze: \n")
    if choice == "1":
        RE_menu()
    elif choice == "2":
        RE_write_to_file( function )
    else:
        print("Kies een valide optie. \n")
        RE_menu()

def RE_menu():
    print("Kies van welke optie gebruik gemaakt wenst te worden:")
    print("Type enkel het nummer van de optie in.")
    print("1: Top 5 interfaces die up en/of down zijn gegaan.")
    print("2: Hoeveel ICMP packets zijn tegengehouden.")
    print("3: Top 20 IP adressen waarvan TCP packets zijn geweigerd.")
    print("4: Welke VLANs veroorzaken de meeste spanning tree problemen.")
    print("5: Handleiding.")
    print("6: Sluit het script af.")
    choice = input("Maak hieronder de keuze: \n")
    if choice == "1":
        RE_top_status_changes()
    elif choice == "2":
        RE_number_of_refused_icmp_packets()
    elif choice == "3":
        RE_top_tcp_denied()
    elif choice == "4":
        RE_vlan_errors()
    elif choice == "5":
        RE_manual()
    elif choice == "6":
        exit()
    else:
        print("Kies een valide optie. \n")
        RE_menu()


RE_menu()
