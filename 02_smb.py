from smb.SMBConnection import SMBConnection

class SMBScanner:

    def __init__(self, ip_target):
        self.ip_target = ip_target
    
    def scann_smb(self):
        resource_dict = {}
        try:
            conn = SMBConnection(
                "",
                "",
                "laptop",
                self.ip_target,
                use_ntlm_v2 = True, 
                is_direct_tcp=True
            )
            if conn.connect(self.ip_target, 445):
                print(f"Connection has been stablished at ip:{self.ip_target}")
                for resource in conn.listShares():
                    if not resource.isSpecial and resource.name not in ['NETLOGON', 'SYSVOL']:
                        files = conn.listPath(resource.name, '/')
                        resource_dict[resource.name] = [file.filename for file in files]         
            else:
                print('Connection was not stablished.')
        except Exception as e:
            print(f"Error during SMB scanning execution.{e}")
        return resource_dict

if __name__ == '__main__':
    sbm_scanner = SMBScanner("192.168.238.132")
    print(sbm_scanner.scann_smb())
