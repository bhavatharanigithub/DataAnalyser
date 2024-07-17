import streamlit as st
import pandas as pd
import hashlib
import plotly.express as px
import json

# Function to handle login
def login(users, email, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    user = next((u for u in users if u['email'] == email), None)
    
    if user:
        if user['password'] == hashed_password:
            return user
        else:
            return None
    else:
        return None

# Function to handle sign-up
def signup(users, new_user):
    if any(u['email'] == new_user['email'] for u in users):
        return False
    users.append(new_user)
    return True

# Function to load data from JSON
def load_data_from_json(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Check if data is not empty
        if not data:
            st.error("Error loading JSON data: File is empty.")
            return pd.DataFrame()

        # Normalize JSON data into DataFrame
        df = pd.json_normalize(data)

        # Ensure all expected columns exist, handle missing columns
        expected_columns = ['end_year', 'intensity', 'sector', 'topic', 'insight', 'url', 'region',
                            'start_year', 'impact', 'country', 'relevance', 'pestle', 'source',
                            'title', 'likelihood', 'published']
        
        missing_columns = [col for col in expected_columns if col not in df.columns]
        if missing_columns:
            st.warning(f"Missing columns in data: {', '.join(missing_columns)}")
            for col in missing_columns:
                df[col] = ''  # Handle missing columns by setting them to empty
        
        # Handle null values
        df.fillna({
            'end_year': 'Unknown',
            'intensity': 0,
            'sector': 'Unknown',
            'topic': 'Unknown',
            'insight': 'No Insight',
            'url': 'No URL',
            'region': 'Unknown',
            'start_year': 'Unknown',
            'impact': 'No Impact',
            'country': 'Unknown',
            'relevance': 0,
            'pestle': 'Unknown',
            'source': 'Unknown',
            'title': 'No Title',
            'likelihood': 0
        }, inplace=True)

        # Convert 'published' to datetime
        if "published" in df.columns:
            df["published"] = pd.to_datetime(df["published"], errors='coerce')
            df.dropna(subset=["published"], inplace=True)

        return df

    except FileNotFoundError:
        st.error(f"Error loading JSON data: File '{filepath}' not found.")
        return pd.DataFrame()
    except json.JSONDecodeError as e:
        st.error(f"Error loading JSON data: {e}")
        return pd.DataFrame()

# Function to show login page
def show_login_page(users):
    st.title("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if email and password:
            user = login(users, email, password)
            if user:
                st.session_state['logged_in'] = True
                st.session_state['user'] = user
                st.success(f"Logged in as {user['username']} ({user['email']})")
                st.experimental_rerun()  # Refresh the page to show the analysis page
            else:
                st.error("Invalid email or password")
        else:
            st.warning("Please enter both email and password")

# Function to show sign-up page
def show_signup_page(users):
    st.title("Sign-Up")
    new_username = st.text_input("New Username")
    new_email = st.text_input("New Email")
    new_password = st.text_input("New Password", type="password")

    if st.button("Sign-Up"):
        if new_username and new_email and new_password:
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            new_user = {
                'username': new_username,
                'email': new_email,
                'password': hashed_password
            }
            success = signup(users, new_user)
            if success:
                st.success(f"User '{new_username}' successfully registered!")
            else:
                st.error(f"Email '{new_email}' already exists. Please choose a different email.")
        else:
            st.warning("Please enter username, email, and password")

# Function to show analysis page
def show_analysis_page(df):
    st.title(":bar_chart: Energy Data Analysis")

    # Remove leading and trailing spaces in all string columns
    df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)
    
    # Ensure 'published' field is used as the date field
    if "published" in df.columns:
        df["published"] = pd.to_datetime(df["published"], errors='coerce')
        df.dropna(subset=["published"], inplace=True)
        
        # Date filter on the main screen
        st.header("Date Filter")
        startDate = pd.to_datetime(df['published']).min()
        endDate = pd.to_datetime(df['published']).max()
        
        date1 = st.date_input('Start Date', startDate)
        date2 = st.date_input('End Date', endDate)
        
        # Sidebar filters
        st.sidebar.header("Filters")
        regions = st.sidebar.multiselect("Pick your Region", df['region'].unique())
        sectors = st.sidebar.multiselect("Pick your Sector", df['sector'].unique())
        topics = st.sidebar.multiselect("Pick your Topic", df['topic'].unique())
        sources = st.sidebar.multiselect("Pick your Source", df['source'].unique())
        pestles = st.sidebar.multiselect("Pick your PESTLE", df['pestle'].unique())
        
        df_filtered = df[(df["published"] >= pd.to_datetime(date1)) & (df["published"] <= pd.to_datetime(date2))]
        
        if regions:
            df_filtered = df_filtered[df_filtered['region'].isin(regions)]
        if sectors:
            df_filtered = df_filtered[df_filtered['sector'].isin(sectors)]
        if topics:
            df_filtered = df_filtered[df_filtered['topic'].isin(topics)]
        if sources:
            df_filtered = df_filtered[df_filtered['source'].isin(sources)]
        if pestles:
            df_filtered = df_filtered[df_filtered['pestle'].isin(pestles)]
        
        if df_filtered.empty:
            st.warning("No data available for the selected filters.")
        else:
            # Ensure columns are numeric
            for col in ['intensity', 'likelihood', 'relevance']:
                df_filtered[col] = pd.to_numeric(df_filtered[col], errors='coerce')
            
            df_filtered.dropna(subset=['intensity', 'likelihood', 'relevance'], inplace=True)

            
            
            
            # Line Chart
            st.write("### Intensity over Time")
            fig = px.line(df_filtered, x="published", y="intensity", title='Intensity over Time')
            st.plotly_chart(fig)
            
            # Bar Plot
            st.write("### Intensity by Region")
            fig = px.bar(df_filtered, x="region", y="intensity", title='Intensity by Region')
            st.plotly_chart(fig)
            
            # Ring/Donut Plot
            st.write("### Distribution of Sectors")
            sector_counts = df_filtered['sector'].value_counts()
            fig = px.pie(values=sector_counts, names=sector_counts.index, hole=0.3, title='Distribution of Sectors')
            st.plotly_chart(fig)
            
            # Histogram
            st.write("### Distribution of Intensity")
            fig = px.histogram(df_filtered, x="intensity", nbins=50, title='Distribution of Intensity')
            st.plotly_chart(fig)
            
            
            st.write("### Intensity vs Likelihood")
            fig = px.scatter(df_filtered, x="intensity", y="likelihood", title='Scatter Plot of Intensity vs Likelihood')
            st.plotly_chart(fig)


    else:
        st.warning("No 'published' column found in data.")


def main():
    st.set_page_config(page_title="Energy Data Analysis Dashboard", layout="wide")
    
    
    users = []
    try:
        with open('users.json', 'r', encoding='utf-8') as f:
            users = json.load(f)
    except FileNotFoundError:
        with open('users.json', 'w', encoding='utf-8') as f:
            json.dump(users, f)
    
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False
    
    if st.session_state['logged_in']:
        # Load data from JSON file
        df = load_data_from_json('jsondata.json')
        show_analysis_page(df)
    else:
        login_or_signup = st.sidebar.radio("Login or Sign-Up", ("Login", "Sign-Up"))
        if login_or_signup == "Login":
            show_login_page(users)
        else:
            show_signup_page(users)

    
    with open('users.json', 'w', encoding='utf-8') as f:
        json.dump(users, f)

if __name__ == "__main__":
    main()








































