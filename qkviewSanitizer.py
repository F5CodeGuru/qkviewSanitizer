#To install the script, simply copy (scp) qkviewSanitizer.py to the /shared directory.
#Nothing else needs to be done, no dependencies.
#Then run qkview command to generate a qkview, this qkview will reside in /var/tmp
#To run the sanitizer
#python qkviewSanitizer.py /var/tmp/hostname.qkview
#This will take a few minutes. After it is done there will be a new sanitized qkview /var/tmp/hostname-sanitized.qkview
#Copy the sanitized version off box using scp and submit to case or https://ihealth.f5.com
#Current features (across all files in the qkview)
#Mask all ip address information (full and partial) Mask all passwords in bigip_user.conf Mask all vlan names Remove all object descriptions
#Last updated: 2016-11-8
    
import fileinput, os, sys, tarfile, re
import traceback
import time
import shutil
import datetime

#Variables
customKeywordsFile = 'customKeywords.txt'
destinationPathExtract = "qkviewextract/"
createTarFilename = sys.argv[1]
listOfPrimaryTgz = []
dictionaryOfSecondaryTgz = {}
newTarfileDirectory = "qkviewOut"
extractCount = 0
bigipPasswordFile= destinationPathExtract + 'config/bigip_user.conf'
bigipBaseFile= destinationPathExtract + 'config/bigip_base.conf'
bigipPasswordRegex = '^\s+encrypted\-password (?P<passwordhash>.*)'
bigipVlanRegex = 'net vlan (?P<vlan>[A-Za-z0-9\-\_\/]+)'
bigipBaseConfHostnameRegex = '^\s*hostname\s*(?P<hostname>.*)'
partitionNameRegex = '\/.*\/'
descriptionRegex = '^\s*description\s*.*'
bigipVlanReplace = 'net vlan sanitizedVlan'
qkviewFilenameString = 'sanitized'
newQkviewPath = '/var/tmp/'
#More specific ip address regex, not used
#\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}
#(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b

eulaMessage = "This script is not officially supported by F5, the script has been tested extensively\n" \
"If you would like to review what was sanitized please view the .log (which is not part of the sanitized qkview) file that is created in the same directory this script is run.\n" \
"Please type yes/y or no/n to accept or decline these terms\n"

#function to prepend root dir to file names
def filter_general(item,root_dir):
    
	full_path = os.path.join(root_dir,item.name)

#qkview extraction function
def extract(tar_url, extract_path):

	print "In extract: " + tar_url
    
    	tar = tarfile.open(tar_url, 'r')

    	if not os.path.isdir(destinationPathExtract):
		print "In mkdir"	
		os.mkdir(destinationPathExtract)
    
    	for item in tar:
	
		listOfPrimaryTgz.append(item.name)
        	tar.extract(item, extract_path)
        
		if item.name.find(".tgz") != -1 or item.name.find(".tar") != -1 or item.name.find("tar.gz") != -1:
	    
			print "In second extract " + destinationPathExtract + item.name + "./" + item.name[:item.name.rfind('/')]
			
	    		listOfFilesInTgz = tar.getnames()
	    		dictionaryOfSecondaryTgz = {item.name : listOfFilesInTgz}
	
	    		try: 

            			extract(destinationPathExtract + item.name, "./" + destinationPathExtract + item.name[:item.name.rfind('/')])
	    
			except:
                
				print "Extraction of gzip wihtin tar failed."
				traceback.print_exc()

#Replace ip address in the form X.X.X.X from the line
def replaceIpInLine(line,DEBUGFILEHANDLE,file):

	lineOld = line
	DEBUGFILEHANDLE.write("File: " + file + " Original line: " + lineOld.strip("\n") + " New line with partial ip scrubbed: " + line)

	return re.sub("(\d+\.\d+\.\d+\.\d+)", "X.X.X.X", line)

#Replace ip addresses that are not complete
def replacePartialIpInLine(line,DEBUGFILEHANDLE,file):

	#This does not handle mask out the first octect of a full ip, but that is ok, we want it to specific so we don't remove potentially useful data that is not an ip
	#The full ip are covered by the replaceIpInLine function which interrogates the line before this
	lineOld = line
	line = re.sub("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){0,2}\/(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){0,3}","X.X.X/X",line)

	DEBUGFILEHANDLE.write("File: " + file + " Original line: " + lineOld.strip("\n") + " New line with ip scrubbed: " + line)
        #Replace partial ip addresses that have no netmask, this causes issues w/ mcp_module.xml
	#Removes too much so commented out
	#line = re.sub("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){0,2}","X.X.X",line)

	return line

#Replace password hashes in bigip_user.conf and get hashes. Use hashes to search other files for the hashes
def getPasswordKeywordsInBigipUserFile(keywordArray):

	if os.path.isfile(bigipPasswordFile):

		for line in fileinput.input(bigipPasswordFile):
			

			if re.match(bigipPasswordRegex, line):

				keywordArray.append(re.match(bigipPasswordRegex, line).group('passwordhash'))

	else:
			
		print "In else"

#function to get keywords such as vlans, then store into an array. Each keyword will be searched for in each line of every file
def getVlanKeywordsInBigipBaseFile(keywordArray):

        if os.path.isfile(bigipBaseFile):

                for line in fileinput.input(bigipBaseFile):

                        vlanRegexMatch =  re.match(bigipVlanRegex, line)

			if vlanRegexMatch:
				
				vlanNameWithPartition = vlanRegexMatch.group('vlan')
                                keywordArray.append(vlanNameWithPartition)
				vlanNameWithoutPartition = re.sub(partitionNameRegex,"",vlanNameWithPartition)
				keywordArray.append(vlanNameWithoutPartition)

        else:

                print "In else"

#function to remove keywords from a line, eg  vlan names with or without the partition
def replaceKeywordInLine(line,keywordArray,DEBUGFILEHANDLE,file):

	for keyword in keywordArray:

		if keyword in line:
		
			line = line.replace(keyword, "keywordSanitized")
			DEBUGFILEHANDLE.write("File: " + file + " Original line: " + line.strip("\n") + " string:  " + keyword + " was replaced with: " + 'keywordSanitized' + "\n")
			
	return line

#(Not currently implemented) Function to build an array of custom/customer defined keywords from a file
def getCustomKeywords(customKeywordsArray):

	for keyword in fileinput.input(customKeywordsFile):

		customKeywordsArray.append(keyword)

#function to replace custom keywords in a line
def replaceCustomKeywordsInLine(line,customKeywordsArray,DEBUGFILEHANDLE,file):

	for keyword in customKeywordsArray:

                if keyword in line:

                        line = line.replace(keyword, "customKeywordSanitized")
			DEBUGFILEHANDLE.write("File: " + file + " Original line: " + line.strip("\n") + " string:  " + keyword + " was replaced with: " + 'customKeywordSanitized' + "\n")
        return line

#function to remove the description field
def replaceDescriptionInLine(line,DEBUGFILEHANDLE,file):

	DEBUGFILEHANDLE.write("File: " + file + " Original line: " + line.strip("\n") + " Entire description was removed.\n")
	return re.sub(descriptionRegex,' description',line) 

#get the bigip hostname from the bigip_base.conf file
def getHostname():

	for line in fileinput.input(destinationPathExtract + 'config/bigip_base.conf'):

		hostnameLineMatch =  re.match(bigipBaseConfHostnameRegex,line)

		if hostnameLineMatch:

			fileinput.close()
			return hostnameLineMatch.group('hostname')

	fileinput.close()
	return "unabletoGetHostname"

#Append to the bigip hostname w/ a .sanitized
def replaceHostnameInMcpModuleXml(hostname,DEBUGFILEHANDLE):

	hostnameReplaceArray = [ 'mcp_module.xml', 'etc/hosts', 'config/bigip_base.conf' ]

	for path in hostnameReplaceArray:

		for line in fileinput.input(destinationPathExtract + path, inplace = 1):

			if hostname in line:		

				print line.replace(hostname,hostname + '.sanitized'),
				DEBUGFILEHANDLE.write("File: " + path + " Original line: " + line.strip("\n") + " string:  " + hostname + " was replaced with: " + hostname+'.sanitized' + "\n")

			else:
		
				print line,

def addSanitizedToHostname(line):

	return  line.strip("\n") + '.sanitized'

#Walk thru all the extracted files from the qkview archive and scrub each line by line
def dirwalk(dir,keywordArray,DEBUGFILEHANDLE):

	for top, dirs, files in os.walk(dir):
    		
		for nm in files:
			
			file = os.path.join(top,nm)

			if os.path.isfile(file):
	
				for line in fileinput.input(file, inplace = 1): 
	
					line = replaceIpInLine(line,DEBUGFILEHANDLE,file)
					line = replacePartialIpInLine(line,DEBUGFILEHANDLE,file)
					line = replaceKeywordInLine(line,keywordArray,DEBUGFILEHANDLE,file)
					line = replaceDescriptionInLine(line,DEBUGFILEHANDLE,file)

					print line,

#Get a list of files to archive for the sanitized qkview 
def returnRecursiveListOfFiles(rootdir):

	fileList = []
	
	for root, subFolders, files in os.walk(rootdir):
		for file in files:
			f = os.path.join(root,file)
			fileList.append(f)

	return fileList

#Create tar archive for sanitized qkview to repackage all files
def createTarFile(newQkviewFilename):

	print "NewQkviewFilename: " + newQkviewFilename
	os.chdir(destinationPathExtract)

	listOfFiles = returnRecursiveListOfFiles('.')
	tar = tarfile.open(newQkviewFilename, "w:gz")

	for file in listOfFiles:
	
		tar.add(file)
		
	tar.close()

#Get current time
def getCurrentTimeString ():

	now = datetime.datetime.now()
	currentTimeString = "-" + str(now.year) + "-" + str(now.month) + "-" + str(now.day) + "-" + str(now.hour) + "-" + str(now.minute) + "-" + str(now.second)

	return currentTimeString

#Create a debug file for logging the changes made
def createDebugFile(qkviewFile):

	currentTimeString = getCurrentTimeString()
	qkviewFileWithTime = qkviewFile + currentTimeString + '.log'
	DEBUGFILEHANDLE = open(qkviewFileWithTime,'w')

	return DEBUGFILEHANDLE

#Function to prompt for the user agreement
def promptEula():
	
	userInput = raw_input(eulaMessage).lower()
	
	if userInput == "yes" or userInput == "y": 

		print("Terms accepted")
	
	else:

		sys.exit("You did not accept the terms ... exiting.")

#Where all execution occurs
def main ():

	promptEula()

	qkviewFilenamePath = ""
	start_time = time.time()

	###Pre execution
	if len(sys.argv) > 1:

        	qkviewFilenamePathArg = sys.argv[1]

	else:

    		print('Error requires qkview archive as first and only argument')
    		sys.exit()
	###End of pre execution

	qkviewFilePath, qkviewFilename = os.path.split(qkviewFilenamePathArg)
	qkviewNewFilename = qkviewFilename.replace('.qkview','.' + qkviewFilenameString + '.qkview')
	currentTimeString = getCurrentTimeString()	
	DEBUGFILEHANDLE = createDebugFile(qkviewFilename)

	try:

    		extract(qkviewFilenamePathArg,destinationPathExtract)
    		print 'Extraction done.'

	except:

    		name = os.path.basename(sys.argv[0])
    		print name[:name.rfind('.')], '<filename>'

	keywordArray = [] 
	customKeywordsArray = [] 
	
	#For some reason the symlink /VERSION -> /VERSION.LTM is not copied correctly, easy fix just remove it copy the file	
	os.remove('qkviewextract/VERSION')
	shutil.copy2('qkviewextract/VERSION.LTM','qkviewextract/VERSION')	
	hostname = getHostname()
	print "Hostname: " + hostname
	replaceHostnameInMcpModuleXml(hostname,DEBUGFILEHANDLE)

	getPasswordKeywordsInBigipUserFile(keywordArray)
	getVlanKeywordsInBigipBaseFile(keywordArray)
	getCustomKeywords(customKeywordsArray)

	dirwalk(destinationPathExtract,keywordArray,DEBUGFILEHANDLE)

	for k,v in dictionaryOfSecondaryTgz.iteritems():
        
		print "DictionaryOfSecondaryTgz key: " + k

        	for i in v:

                	print "DictionaryOfSecondaryTgz value: " + i

	print "Sanitized qkview filename: " + qkviewNewFilename

	createTarFile(newQkviewPath + qkviewNewFilename)

	DEBUGFILEHANDLE.close()
	print("Runtime: %f seconds" % (time.time() - start_time))

main()
