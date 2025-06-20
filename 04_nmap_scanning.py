import subprocess

class NmapExecutor:

    def __init__(self, commands):
        self.commands = commands
    
    #----- Method that run nmap commands -----#
    def run(self):
        result = subprocess.run(
             self.commands, 
             stdout = subprocess.PIPE, 
             stdin = subprocess.PIPE, 
             text = True)

        if result.returncode == 0:
            print("Nmap Output:\n")
            print(result.stdout)
        else:
            print("No output in nmap execution")
    
if __name__ == '__main__':
        nmap = NmapExecutor(['nmap','-PS','192.168.1.0/24'])
        nmap.run()