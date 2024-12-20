import re

print("""
      String Extractor Script - Find Possible IPv4 Addresses, URLs, and Filenames/Extensions within a file.\n
      Target use is for when you extract strings from a malware file and don't want to dig through line by line\n
      for pertinent information.\n
      When prompted for the filename, include either the full path of the file including extension or place script\n
      in the working directory where the target file is located and type the filename alone including extension.\n
      Copyright 2023, 0xHyp3rion
      """)


filename = input("Enter Filename:\n")


#   Opens and reads the file.
with open(filename) as fh:
    fstring = fh.readlines()

#   Declaring regex patterns for results:
ipv4Pattern = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
URLPattern = re.compile(r'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)')
FilesPattern = re.compile(r'[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[-a-zA-Z0-9]{3}')
ExeFilesPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(bin|cmd|com|cpl|exe|gadget|inf1|ins|inx|isu|job|jse|lnk|msc|msi|msp|mst|paf|pif|ps1|reg|rgs|scr|sct|shb|shs|u3p)(?![\w\d])') 
ScriptFilesPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(bat|asp|aspx|htm|html|js|vb|vbs|wsf|wsh|py|c|cpp|sh|vbscript|vbe|u3p|shs|shb|sct|scr|rgs|pif|paf|jse|csh)(?![\w\d])')
DLLFilesPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(dll)(?![\w\d])')
AudioPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(aif|cda|mid|midi|mp3|mpa|ogg|wav|wma|wpl)(?![\w\d])')
CompressedPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(7z|arj|deb|pkg|rar|rpm|tar.gz|z|zip)(?![\w\d])')
DiscMediaPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(bin|dmg|iso|toast|vcd)(?![\w\d])')
DataPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(csv|dat|db|dbf|log|mdb|sav|sql|tar|xml)(?![\w\d])')
EmailPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(email|eml|emlx|msg|oft|ost|pst|vcf)(?![\w\d])')
FontsPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(fnt|fon|otf|ttf)(?![\w\d])')
ImagesPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(ai|bmp|gif|ico|jpeg|jpg|png|ps|psd|svg|tif|tiff|webp)(?![\w\d])')
WebPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(asp|aspx|cer|cfm|cgi|pl|css|htm|html|js|jsp|part|php|py|rss|xhtml)(?![\w\d])')
PresentationPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(key|odp|pps|ppt|pptx)(?![\w\d])')
ProgrammingPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(c|cgi|pl|class|cpp|cs|h|java|jar|php|py|sh|swift|vb)(?![\w\d])')
SpreadsheetPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(ods|xls|xlsm|xlsx)(?![\w\d])')
SystemPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(bak|cab|cfg|cpl|cur|dll|dmp|drv|icns|ico|ini|lnk|msi|sys|tmp)(?![\w\d])')
VideoPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(3g2|g3p|avi|flv|h264|m4v|mkv|mov|mp4|mpg|mpeg|rm|swf|vob|webm|wmv)(?![\w\d])')
WordPattern = re.compile(r'[-a-zA-Z0-9._~]{1,}\.(?<![\w\d])(doc|docx|odt|pdf|rtf|tex|txt|wpd)(?![\w\d])')

#   Initialize list objects:
ipv4List = []
URLList = []
FilesList = []
ExeFilesList = []
ScriptFilesList = []
DLLFilesList = []
AudioList = []
CompressedList = []
DiscMediaList = []
DataList = []
EmailList = []
FontsList = []
ImagesList = []
WebList = []
PresentationList = []
ProgrammingList = []
SpreadsheetList = []
SystemList = []
VideoList = []
WordList = []

#   For loop - for each line in fstring, append a new line with the results of the regex pattern.
for line in fstring:
    ipv4List.append(ipv4Pattern.search(line))
    URLList.append(URLPattern.search(line))
    FilesList.append(FilesPattern.search(line))
    ExeFilesList.append(ExeFilesPattern.search(line))
    ScriptFilesList.append(ScriptFilesPattern.search(line))
    DLLFilesList.append(DLLFilesPattern.search(line))
    AudioList.append(AudioPattern.search(line))
    CompressedList.append(CompressedPattern.search(line))
    DiscMediaList.append(DiscMediaPattern.search(line))
    DataList.append(DataPattern.search(line))
    EmailList.append(EmailPattern.search(line))
    FontsList.append(EmailPattern.search(line))
    ImagesList.append(ImagesPattern.search(line))
    WebList.append(WebPattern.search(line))
    PresentationList.append(PresentationPattern.search(line))
    ProgrammingList.append(ProgrammingPattern.search(line))
    SpreadsheetList.append(SpreadsheetPattern.search(line))
    SystemList.append(SystemPattern.search(line))
    VideoList.append(VideoPattern.search(line))
    WordList.append(WordPattern.search(line))

#   Filter out the "None" results
ipv4ListNew = filter(None, ipv4List)
URLListNew = filter(None, URLList)
FilesListNew = filter(None, FilesList)
ExeFilesListNew = filter(None, ExeFilesList)
ScriptFilesListNew = filter(None, ScriptFilesList)
DLLFilesListNew = filter(None, DLLFilesList)
AudioListNew = filter(None, AudioList)
CompressedListNew = filter(None, CompressedList)
DiscMediaListNew = filter(None, DiscMediaList)
DataListNew = filter(None, DataList)
EmailListNew = filter(None, EmailList)
FontsListNew = filter(None, FontsList)
ImagesListNew = filter(None, ImagesList)
WebListNew = filter(None, WebList)
PresentationListNew = filter(None, PresentationList)
ProgrammingListNew = filter(None, ProgrammingList)
SpreadsheetListNew = filter(None, SpreadsheetList)
SystemListNew = filter(None, SystemList)
VideoListNew = filter(None, VideoList)
WordListNew = filter(None, WordList)


#   Print the results on individual new lines
print("""
===================================
****** POSSIBLE IPV4 MATCHES ******
===================================
      """)
print(*ipv4ListNew, sep="\n")

print("""
===================================
****** POSSIBLE URL MATCHES *******
===================================
      """)
print(*URLListNew, sep="\n")

print("""
===================================
** POSSIBLE UNCATEGORIZED MATCHES *
===================================
      """)
print(*FilesListNew, sep="\n")

print("""
===================================
**** POSSIBLE SCRIPT MATCHES ******
===================================
      """)
print(*ScriptFilesListNew, sep="\n")

print("""
===================================
****** POSSIBLE DLL MATCHES *******
===================================
      """)
print(*DLLFilesListNew, sep="\n")

print("""
===================================
***** POSSIBLE AUDIO MATCHES ******
===================================
      """)
print(*AudioListNew, sep="\n")

print("""
===================================
*** POSSIBLE COMPRESSED MATCHES ***
===================================
      """)
print(*CompressedListNew, sep="\n")

print("""
===================================
***** POSSIBLE MEDIA MATCHES ******
===================================
      """)
print(*DiscMediaListNew, sep="\n")

print("""
===================================
***** POSSIBLE DATA MATCHES *******
===================================
      """)
print(*DataListNew, sep="\n")

print("""
===================================
***** POSSIBLE EMAIL MATCHES ******
===================================
      """)
print(*EmailListNew, sep="\n")

print("""
===================================
****** POSSIBLE FONT MATCHES ******
===================================
      """)
print(*FontsListNew, sep="\n")

print("""
===================================
***** POSSIBLE IMAGE MATCHES ******
===================================
      """)
print(*ImagesListNew, sep="\n")

print("""
===================================
****** POSSIBLE WEB MATCHES *******
===================================
      """)
print(*WebListNew, sep="\n")

print("""
===================================
** POSSIBLE PRESENTATION MATCHES **
===================================
      """)
print(*PresentationListNew, sep="\n")

print("""
===================================
** POSSIBLE PROGRAMMING MATCHES ***
===================================
      """)
print(*ProgrammingListNew, sep="\n")

print("""
===================================
** POSSIBLE SPREADSHEET MATCHES ***
===================================
      """)
print(*SpreadsheetListNew, sep="\n")

print("""
===================================
**** POSSIBLE SYSTEM MATCHES ******
===================================
      """)
print(*SystemListNew, sep="\n")

print("""
===================================
***** POSSIBLE VIDEO MATCHES ******
===================================
      """)
print(*VideoListNew, sep="\n")

print("""
===================================
***** POSSIBLE WORD MATCHES *******
===================================
      """)
print(*WordListNew, sep="\n")