class IsValid:
    @staticmethod
    def addr(ip_addr):
        octets = ip_addr.split(".")
        if len(octets) != 4:
            # print "must have 4 octets!"
            return False
        else:
            for i, octet in enumerate(octets):
                try:
                    octets[i] = int(octet)
                except ValueError:
                    # invalid input if not convertible to integer
                    return False
            first_octet, second_octet, third_octet, fourth_octet = octets
            valid_ip = True
            if first_octet < 1:
                valid_ip = False
            elif first_octet > 223:
                valid_ip = False
            elif first_octet == 127:
                valid_ip = False
            if first_octet == 169 and second_octet == 254:
                valid_ip = False
            # Check 2nd - 4th octets
            for octet in (second_octet, third_octet, fourth_octet):
                if (octet < 0) or (octet > 255):
                    valid_ip = False
        return valid_ip

    @staticmethod
    def port(port):
        try:
            port_int = int(port)
        except ValueError:
            return False
        if 0 < port_int < 65536:
            return True
        else:
            return False
