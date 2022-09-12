from email.policy import default
from turtle import color, width
import streamlit as st
import pandas as pd
import numpy as np
from matplotlib import cm
import matplotlib.pyplot as plt
from PIL import Image




# Set web info 
st.set_page_config(page_title="Visualization of CTI-based Risk Assessment in Healthcare", page_icon=":bar_chart:", layout="wide")



df_breach = pd.read_csv("U.S.breach_report.csv")
df_vuln = pd.read_csv("Threats_new1.csv")
df_mitigation = pd.read_csv("Mitigations.csv")

breachMap=df_breach["Breach Type"].unique()
breachMap.sort()
threatMap1=df_vuln["Threat Type"].unique()
threatMap1.sort()

assetMap=["Desktop Computer", "Electronic Medical Record", "Email",
        "Laptop", "Network Server", "Other Portable Electronic Device",
        "Paper/Films", "Other"]



colors = ["purple", "blue", "lightblue", "gray", "red", "green", "lightgreen", "orange", "black", "pink"]

# Sidebar
st.sidebar.header("Please select here:👇")
risk = st.sidebar.selectbox(
    "Please choose Risk Type:",
    ("Data Breach", "Vulnerability")
    )

country = st.sidebar.selectbox(
    "Please choose location:",
    ("United States", "United Kingdom", "China")
    )

years = st.sidebar.selectbox(
    "Please choose year:",
    ("2013", "2014", "2015", "2016", "2017",
    "2018", "2019", "2020", "2021", "2022",
    "past-now")
    )


with st.sidebar.form("form1"):
    st.write("Please choose mitigations from (organization):")
    AVERTIUM = st.checkbox("AVERTIUM")
    Cisecurity = st.checkbox("Cisecurity")
    MITRE = st.checkbox("MITRE")
    CISA = st.checkbox("CISA (General Mitigations)")
    button1 = st.form_submit_button()



st.title(":bar_chart: Visualization of CTI-based Risk Assessment in Healthcare")
st.markdown("##")


# Columns layout
rows = df_vuln.shape[0]

# Dataset-"vulnerability"
if "Vulnerability" in risk:
    threat_select=[]
    col1, col2, col3, col4 = st.columns(4)
    # Info
    with col1:
        st.subheader("Year:")
        if "United States" in country:
            st.subheader(f"{df_vuln.Year[len(df_vuln)-1]} - {df_vuln.Year[0]}")
    with col2:
        st.subheader("Type of threats:")
        if "United States" in country:
            # st.subheader(f"{len(threatMap1)}")
            threat_select=st.selectbox(
                f"Please select type (total: {len(threatMap1)}):",
                options=threatMap1
            )
    with col3:
        st.subheader("Number of threats:")
        if "United States" in country:
            rows = df_vuln.shape[0]
            st.subheader(f"{rows}")
    with col4:
        st.subheader("Country:")
        if "United States" in country:
            st.subheader(f"US")
        if "United Kingdom" in country:
            st.subheader(f"UK")   
        if "China" in country:
            st.subheader(f"China")
    
    # Delimiter
    st.markdown("""---""")
    
    if "United States" in country:
        # st.dataframe(df_vuln)
        st.markdown("- **Below is CVE vulnerabilities in healthcare from [U.S. NVD](https://nvd.nist.gov/vuln/search) (NATIONAL VULNERABILITY DATABASE):**")
        # Interactive forms
        # st.write(df_vuln)
        see_data = st.expander('You can click here to see the dataset first 👉')
        with see_data:
            st.dataframe(data=df_vuln)
    
    # @st.cache(persist=True)
    def bar(year):
        fig = plt.figure()
        df = df_vuln[["Year","Threat Type"]][df_vuln.Year==year]
        df["Threat Type"].value_counts().sort_index().plot.bar(color=colors,width=0.8)
        plt.ylabel('Number') 
        plt.xlabel('Threat Type') 
        plt.title("Cyber Threat distribution in " + str(year))
        st.pyplot(fig)
        return
    
    threatGroup=df_vuln.groupby(["Threat Type","Year"]).size()
    
    # @st.cache(suppress_st_warning=True)
    # @st.cache(persist=True)
    def line(threat):
        fig = plt.figure()
        plt.ylabel('Number') 
        plt.title(threat)
        threatGroup[threat].T.plot(kind="line",marker="o")
        # st.line_chart(threatGroup[threat])
        st.pyplot(fig)
        return
    
    
    col1space, col1, col2space, col2, col3space = st.columns((1,2,.5,2,1))
    with col1:
        if "United States" in country:
            for i in range(2013,2023):
                if str(i) in years:
                    bar(i)
                    break
                else:
                    continue
    with col2:
        for item in threatMap1:    
            if item in threat_select:
                line(item)

    
    col1, col2, col3, col4 = st.columns(4)
    if "past-now" in years:
        if "United States" in country:
            for i in range(len(threatMap1)):
                    if i%4 == 0:
                        with col1:
                            line(threatMap1[i])
                    elif i%4 == 1:
                        with col2:
                            line(threatMap1[i])
                    elif i%4 == 2:
                        with col3:
                            line(threatMap1[i])
                    elif i%4 == 3:
                        with col4:
                            line(threatMap1[i])

    threatType=st.multiselect(
        f"Please select vulnerability threat type (total: {len(threatMap1)}) to see mitigations in healthcare:",
        options=threatMap1
    )

    # st.markdown("**Below are mitigations from [CISA](https://www.cisa.gov/uscert/ncas/alerts/aa20-245a):**")
    for item in threatMap1:
        if item in threatType:
            df_m=df_mitigation[df_mitigation["Threat/Breach Type"]==item]
            df_m.index=np.arange(1,len(df_m)+1)
            st.write(df_m)
    st.markdown("> *References: [CISA](https://www.cisa.gov/uscert/ncas/alerts/aa20-245a)*")
    st.markdown("##")
            


M1 = pd.read_csv("Mitigations-AVERTIUM.csv")
M2 = pd.read_csv("Mitigations-CIS.csv")
M3 = pd.read_csv("Mitigations-CISA.csv")

# Dataset-"data breach"
if "Data Breach" in risk:
    risk_select=[]
    asset_select=[]
    col1, col2, col3, col4, col5 = st.columns(5)
    # info
    with col1:
        st.subheader("Year:")
        if "United States" in country:
            st.subheader(f"{df_breach.Year[len(df_breach)-1]} - {df_breach.Year[0]}")
    with col2:
        st.subheader("Type of risks:")
        if "United States" in country:           
            # st.subheader(f"{len(breachMap)}")
            risk_select=st.selectbox(
                f"Please select type (total: {len(breachMap)}):",
                options=breachMap
            )
    with col3:
        st.subheader("Number of risks:")
        if "United States" in country:
            rows = df_breach.shape[0]
            st.subheader(f"{rows}")
    with col4:
        st.subheader("Country:")
        if "United States" in country:
            st.subheader(f"US")
        if "United Kingdom" in country:
            st.subheader(f"UK")   
        if "China" in country:
            st.subheader(f"China")
    with col5:
        st.subheader("Asset:")
        if "United States" in country:
            asset_select=st.selectbox(
                f"Please select asset (total: {len(assetMap)}):",
                options=assetMap
            )
    
    # Delimiter
    st.markdown("""---""")
    
    if "United States" in country:
        st.markdown("- **Below is breach dataset in healthcare from [U.S. Department of Health and Human Services](https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf):**")
        # Interactive forms
        # st.write(df_breach)
        see_data = st.expander('You can click here to see the dataset first 👉')
        with see_data:
            st.dataframe(data=df_breach)
    
    
    def bar(year):
        fig = plt.figure()
        df = df_breach[["Year","Breach Type"]][df_breach.Year==year]
        df["Breach Type"].value_counts().sort_index().plot.bar(color=colors,width=0.8)
        plt.ylabel('Number') 
        plt.xlabel('Risk Type') 
        plt.title("Risk distribution in " + str(year))
        st.pyplot(fig)
        return
    
    breachGroup=df_breach.groupby(["Breach Type","Year"]).size()
    assetGroup=df_breach.groupby(["Breache location (Asset)", "Breach Type"]).size()
    assetGroup.rename("Percentage (%)",inplace=True)
    
    # @st.cache(persist=True)
    # @st.cache(suppress_st_warning=True)
    def line(threat):
        fig = plt.figure()
        plt.ylabel('Number') 
        plt.title(threat)
        breachGroup[threat].T.plot(kind="line",marker="o")
        # st.line_chart(threatGroup[threat])
        st.pyplot(fig)
        return
    
    col1, col2, col3 = st.columns(3)
    with col1:
        if "United States" in country:
            for i in range(2013,2023):
                if str(i) in years:
                    bar(i)
                    break
                else:
                    continue
    with col2:
        for item in breachMap:    
            if item in risk_select:
                line(item)
    with col3:
        for item in assetMap:
            if item in asset_select:
                fig = plt.figure()
                # plt.ylabel('Number') 
                plt.title(f"Data breach of {item}")
                # assetGroup[item].T.plot(kind="pie")
                assetGroup[item].plot.pie(autopct='%.2f',figsize=(7,7))
                # st.line_chart(threatGroup[threat])
                st.pyplot(fig)
                break
    
    col1, col2, col3, col4 = st.columns(4)
    if "past-now" in years:
        if "United States" in country:
            for i in range(len(breachMap)):
                    if i%4 == 0:
                        with col1:
                            line(breachMap[i])
                    elif i%4 == 1:
                        with col2:
                            line(breachMap[i])
                    elif i%4 == 2:
                        with col3:
                            line(breachMap[i])
                    elif i%4 == 3:
                        with col4:
                            line(breachMap[i])
    
    breachType=st.multiselect(
        f"Please select data breach type (total: {len(breachMap)}) to see mitigations in healthcare:",
        options=breachMap
    )

    for item in breachType:
        if item == "Unknown":
            mitigation=df_mitigation.Mitigations[df_mitigation["Threat/Breach Type"]==item]
            # mitigation=df_mitigation.loc[df_mitigation["Threat/Breach Type"]==item]
            mitigation.index=np.arange(1,len(mitigation)+1)
            st.markdown(f"- Mitigations for **{item}**: ")
            st.write(mitigation)
        else:
            df_m0=df_mitigation.Mitigations[df_mitigation["Threat/Breach Type"]==item]
            df_m0.index=np.arange(1,len(df_m0)+1)
            df_m1=df_m0[1]
            df_m2=M1["Mitigations"][M1.Object==df_m1] 
            df_m2.index=np.arange(1,len(df_m2)+1)
            st.markdown(f"- Mitigations for **{item}**: ")
            st.write(df_m2)
        
    st.markdown("> *References: [CISA](https://www.cisa.gov/uscert/ncas/alerts/aa20-245a), [AVERTIUM](https://www.avertium.com/resources/threat-reports/cyber-threats-in-the-healthcare-industry).*")
    st.markdown("##")


# @st.cache(persist=True)
def risk_mitigation(miti):
    for i in range(len(miti.Object.unique())):
        step = st.expander(f"Mitigation{i+1}: {miti.Object.unique()[i]}")
        with step:
            # st.dataframe(data=miti["Mitigations"][miti.Object=="Physical"])
            # mitigation=miti["Mitigations"][miti.Object==miti.Object.unique()[i]].reset_index(drop=True).shift()[1:]
            mitigation=miti["Mitigations"][miti.Object==miti.Object.unique()[i]]
            mitigation.index=np.arange(1,len(mitigation)+1)
            st.write(mitigation)
            

if AVERTIUM & button1:
    st.markdown("- **Below are risk mitigations from [AVERTIUM](https://www.avertium.com/resources/threat-reports/cyber-threats-in-the-healthcare-industry):**")
    organ1=risk_mitigation(M1)
    st.markdown("> *References: [AVERTIUM](https://www.avertium.com/resources/threat-reports/cyber-threats-in-the-healthcare-industry)*")

if Cisecurity & button1:
    st.markdown("- **Below are risk mitigations from [Cisecurity](https://www.cisecurity.org/insights/blog/cyber-attacks-in-the-healthcare-sector):**")
    organ2=risk_mitigation(M2)
    st.markdown("> *References: [Cisecurity](https://www.cisecurity.org/insights/blog/cyber-attacks-in-the-healthcare-sector)*")

if MITRE & button1:
    st.markdown("- **Below are TTP (Tactics/Techniques//Procedures) and risk mitigations from [MITRE](https://attack.mitre.org/mitigations/enterprise/):**")
    risk1 = st.expander("Mitigation1: Ransomware")
    with risk1:
        st.markdown("""
        - **[**[T1598](https://attack.mitre.org/techniques/T1598/)**]** Phishing for Information
        - **[**[T1190](https://attack.mitre.org/techniques/T1190/)**]** Exploit Public-Facing Application
        - **[**[T1562](https://attack.mitre.org/techniques/T1562/)**]** Impair Defense
        - **[**[T1567](https://attack.mitre.org/techniques/T1567/)**]** Exfiltration Over Web Service
        - **[**[T1566](https://attack.mitre.org/techniques/T1566/)**]** Phishing
        - **[**[T1133](https://attack.mitre.org/techniques/T1133/)**]** External Remote Services
        """
        )
    risk2 = st.expander("Mitigation2: Data Breaches")
    with risk2:
        st.markdown("""
        - **[**[T1213](https://attack.mitre.org/techniques/T1213/)**]** Data from Information Repositories
        - **[**[T1602\]](https://attack.mitre.org/techniques/T1602/)**]** Data from Configuration Repository
        - **[**[T1531](https://attack.mitre.org/techniques/T1531/)**]** Account Access Removal
        - **[**[T1486](https://attack.mitre.org/techniques/T1486/)**]** Data Encrypted for Impact
        - **[**[T1485](https://attack.mitre.org/techniques/T1485/)**]** Data Destruction
        """
        )
    risk3 = st.expander("Mitigation3: DDoS")
    with risk3: 
        st.markdown("""
        - **[**[T1583](https://attack.mitre.org/techniques/T1583/)**]** Acquire Infrastructure
        - **[**[T1595](https://attack.mitre.org/techniques/T1595/)**]** Active Scanning
        - **[**[T1589](https://attack.mitre.org/techniques/T1589/)**]** Gather Victim Identity Information
        - **[**[T1584](https://attack.mitre.org/techniques/T1584/)**]** Compromise Infrastructure
        - **[**[T1583](https://attack.mitre.org/tactics/TA0042/)**]** Resource Development
        - **[**[T1498](https://attack.mitre.org/techniques/T1498/)**]** Network Denial of Service
        """
        )
    risk4 = st.expander("Mitigation4: Insider Threats")
    with risk4:
        st.markdown("""
        - **[**[T1199](https://attack.mitre.org/techniques/T1199/)**]** Trusted Relationship
        - **[**[T1190](https://attack.mitre.org/techniques/T1190/)**]** Exploit Public-Facing Application
        - **[**[T1204](https://attack.mitre.org/techniques/T1204/)**]** User Execution
        """
        )
    risk5 = st.expander("Mitigation5: Business Email Compromise and Fraud Scams")
    with risk5:        
        st.markdown("""
        - **[**[T1397](https://attack.mitre.org/versions/v7/techniques/T1397/)**]** Spear-phishing for Information
        - **[**[T1598](https://attack.mitre.org/techniques/T1598/)**]** Phishing for Information
        - **[**[T1591](https://attack.mitre.org/techniques/T1591/)**]** Gather Victim Org Information
        - **[**[T1548](https://attack.mitre.org/techniques/T1548/)**]** Abuse Elevation Control Mechanism
        """
        )
    st.markdown("> *References: [MITRE](https://attack.mitre.org/mitigations/enterprise/)*")

if CISA & button1:
    st.markdown("- **Below are risk mitigations from [CISA](https://www.cisa.gov/uscert/ncas/alerts/aa20-245a) (General Mitigations):**")
    organ3=risk_mitigation(M3)
    st.markdown("> *References: [CISA](https://www.cisa.gov/uscert/ncas/alerts/aa20-245a)*")

if True not in (AVERTIUM, Cisecurity, CISA, MITRE):
    if button1:
        st.warning(":point_left: :warning: Please :ballot_box_with_check: at least one item before submissing!")



# fig=plt.figure()
# df_vuln["Threat Type"].value_counts().sort_index().plot.bar(color=colors,width=0.8)
# # plt.bar(x=df_vuln.loc[:,"Threat Type"],height=df_vuln.loc[:,"Threat Type"],color="green",width=0.8)
# st.pyplot(fig)


# Delimiter
st.markdown("""---""")
# FAIR Model

FAIR=st.sidebar.checkbox('The FAIR Model')
if FAIR:
    st.markdown("- **The FAIR Model is shown below. :point_down:**")
    col1,col2,col3 = st.columns((2,4,2))
    with col2:
        image = Image.open('FAIR Model.jpg')
        st.image(image, caption='The FAIR Model')





# Threat Event Frequency
TEF=st.sidebar.slider(
    "Please choose Probability of Threat (%):",
    0, 100, (0, 10)
    )

if (50,100) in TEF:
    st.dataframe(data=df_vuln)


# Loss Magnitude
LM=st.sidebar.select_slider(
    "Please choose Loss Magnitude:",
    options=["Very Low","Low","Moderate","High","Very High"]
    )


# Mitigation Cost
MC=st.sidebar.select_slider(
    "Please choose Mitigation Cost:",
    options=["Very Low","Low","Moderate","High","Very High"]
    )

if "High" in LM:
    st.markdown("- **Below are risk mitigations from [AVERTIUM](https://www.avertium.com/resources/threat-reports/cyber-threats-in-the-healthcare-industry):**")
    organ1=risk_mitigation(M1)

if "High" in MC:
    st.markdown("- **Below are risk mitigations from [Cisecurity](https://www.cisecurity.org/insights/blog/cyber-attacks-in-the-healthcare-sector):**")
    organ2=risk_mitigation(M2)



# Hide streamlit default format
hide_st_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            header {visibility: hidden;}
            </style>            """

st.markdown(hide_st_style, unsafe_allow_html=True)