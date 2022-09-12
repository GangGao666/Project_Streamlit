
# -*- coding: utf-8 -*-





from posixpath import split
import pandas as pd
import csv




# Dataset1
# Data Crawling
p1 = 1
for i in range(0,81,20):  # Crawl all 5 pages of data
	url = 'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=healthcare&results_type=overview&form_type=Basic&search_type=all&startIndex=%s' % (str(i))
	tb1 = pd.read_html(url)[0]   #The required table is the 1st table in the website
	tb1.to_csv('Threats.csv', mode='a+', encoding='utf_8_sig', index=False)
	print("Page " + str(p1) + " crawl completed! " + str(len(tb1)) + " rows.")
	tb = pd.read_csv("Threats.csv")
	p1 += 1
print(tb.shape)    # (89, 3)
# print(tb.head())

p2 = 1
for i in range(0,261,20):  # Crawl all 14 pages of data
	url = 'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=hospital&results_type=overview&form_type=Basic&search_type=all&startIndex=%s' % (str(i))
	tb2 = pd.read_html(url)[0]   #The required table is the 1st table in the website
	tb2.to_csv('Threats.csv', mode='a+', encoding='utf_8_sig', index=False)
	print("Page " + str(p2) + " crawl completed! " + str(len(tb2)) + " rows.")
	tb = pd.read_csv("Threats.csv")
	p2 += 1
print(tb.shape)    # (368, 3)

p3 = 1
for i in range(0,141,20):  # Crawl all 8 pages of data
	url = 'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=patient&results_type=overview&form_type=Basic&search_type=all&startIndex=%s' % (str(i))
	tb3 = pd.read_html(url)[0]   #The required table is the 1st table in the website
	tb3.to_csv('Threats.csv', mode='a+', encoding='utf_8_sig', index=False)
	print("Page " + str(p3) + " crawl completed! " + str(len(tb3)) + " rows.")
	tb = pd.read_csv("Threats.csv")
	p3 += 1
print(tb.shape)    # (527, 3)


# Data pre-processing
df0 = pd.read_csv("Threats.csv")
# print(df0.head())

# is NA
df0.isna().any()
df0[df0.isnull().values==True]

# Data cleaning, de-duplication
df0[df0.duplicated()].count()
# nodup = df0[-df0.duplicated()]
nodup = df0.drop_duplicates(subset = ['Vuln ID'], keep = "first", inplace = False)
# nodup[nodup.duplicated()].count()
nodup.shape		# (460,3)
nodup.drop(nodup[nodup.loc[:,"Vuln ID"] == "Vuln ID"].index, inplace = True)
nodup.shape		# (459,3)

# Data sorting
nodup.sort_values(by = "Vuln ID", ascending = False, inplace = True)
nodup.to_csv('Threats_new.csv', mode = "w+", encoding='utf_8_sig', index=False)

# Removing outliers
df1 = pd.read_csv("Threats_new.csv")
noOutlier = df1.copy(deep = True)	# Copy both the index and data of the object
row_remove = []
for row in range(len(df1)):	
	if df1.loc[row, "Summary"].casefold().find("non-medical device") == -1:
		continue
	else:
		# print(row)
		row_remove.append(row)
		noOutlier.drop([row], inplace = True)

noOutlier.shape		# (450, 3)
noOutlier.to_csv('Threats_new.csv', mode = "w+", encoding='utf_8_sig', index=False)


# Keyword Matching & Extraction
kwordMap=["XSS", "SQL injection", "Denial of service", "Overflow", 
		"SSL", "Unauthorized", "Access", "Privilege", 
		"Permissions", "Cleartext", "Input", "Firmware", 
		"Password", "Credential", "Authentication", "Authenticated", 
		"Other vuln"]

threatMap=["XSS Attack", "SQL Injection", "Denial of service", "Buffer Overflow", 
		"SSL Injection", "Insufficient Authorization", "Insufficient Authentication", "Insufficient Authorization", 
		"Insufficient Authorization", "Information Leakage", "Improper Input Handling", "Information Leakage", 
		"Brute Force", "Insufficient Process Validation", "Insufficient Authentication", "Insufficient Process Validation", 
		"Other vuln"]
# 

# threatMap=["XSS attack", "SQL injection", "DDoS attack", "Malware", 
# 		"Buffer overflow", "SSL injection", "User access issue", "User access issue", 
# 		"User access issue", "User access issue", "Data storage in cleartext", "Input validation", 
# 		"Firmware issue", "Code debugging issue", "Default password", "Credential exposure", 
# 		"Authentication protocol vuln", "Account authentication issue", "Version vuln", "Other vuln"]


# space=" "
# kwords_new=space.join(kwords).split()
# k1=df1.loc[0][1].split()
# set_k2=set(k1) & set(kwords_new)

df2 = pd.read_csv("Threats_new.csv")
df2.shape		# (450, 3)
kwList=[]
threatList = []
def kwordMactching(df):
	for row in range(len(df)):
		for i in range(len(kwordMap)):
			if df.loc[row][1].casefold().find(kwordMap[i].casefold()) != -1:
				kwList.append(kwordMap[i])
				threatList.append(threatMap[i])
				break
			else:
				if i==len(kwordMap)-1:
					kwList.append(kwordMap[-1])
					threatList.append(threatMap[-1])
	return threatList
threat=kwordMactching(df2)
kwList.count("Other vuln")		# 29
# for i in range(len(kwList)):
#     if kwList[i]=="Other vuln":
#         print(i)    # Print keyword index
pd.value_counts(kwList)
pd.value_counts(threatList)


# Generate new dataset
df2["Keyword"] = kwList
df2["Threat Type"] = threatList
year = []
for item in df2.loc[:, "Vuln ID"]:
	year.append(item.split("-")[1])
	# year.append(int(item.split("-")[1]))

df2["Year"] = year
df2.to_csv('Threats_new1.csv', mode = "w+", encoding='utf_8_sig', index=False)




# Dataset2
df_breach = pd.read_csv("U.S.breach_report.csv")
yearList = []
for item in df_breach.loc[:, "Breach Submission Date"]:
	yearList.append(item.split("/")[2])
	# year.append(int(item.split("-")[1]))

df_breach["Year"] = yearList
df_breach.to_csv('U.S.breach_report.csv', mode = "w+", encoding='utf_8_sig', index=False)





