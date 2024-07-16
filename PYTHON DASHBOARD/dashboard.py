import streamlit as st
import pandas as pd
import hashlib
import sqlite3
from sqlalchemy import create_engine
import plotly.express as px

# Function to handle login
def login(db_conn, email, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    cursor = db_conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    
    st.write(f"Email: {email}")
    st.write(f"Hashed Password: {hashed_password}")
    
    if user:
        stored_password = user[3]  # Ensure this index is correct for the password column
        st.write(f"Stored Password: {stored_password}")
        if stored_password == hashed_password:
            return user
        else:
            return None
    else:
        return None

# Function to handle sign-up
def signup(db_conn, username, email, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    cursor = db_conn.cursor()
    
    try:
        cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, hashed_password))
        db_conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

# Function to load data from SQL database
def load_data_from_sql(db_engine, query):
    with db_engine.connect() as connection:
        df = pd.read_sql(query, connection)
    return df

# Function to show login page
def show_login_page(db_conn):
    st.title("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if email and password:
            user = login(db_conn, email, password)
            if user:
                st.session_state['logged_in'] = True
                st.session_state['user'] = user
                st.success(f"Logged in as {user[1]} ({user[2]})")
                st.experimental_rerun()  # Refresh the page to show the analysis page
            else:
                st.error("Invalid email or password")
        else:
            st.warning("Please enter both email and password")

# Function to show sign-up page
def show_signup_page(db_conn):
    st.title("Sign-Up")
    new_username = st.text_input("New Username")
    new_email = st.text_input("New Email")
    new_password = st.text_input("New Password", type="password")

    if st.button("Sign-Up"):
        if new_username and new_email and new_password:
            success = signup(db_conn, new_username, new_email, new_password)
            if success:
                st.success(f"User '{new_username}' successfully registered!")
            else:
                st.error(f"Email '{new_email}' already exists. Please choose a different email.")
        else:
            st.warning("Please enter username, email, and password")

# Function to show analysis page
def show_analysis_page():
    st.title(":bar_chart: Energy Data Analysis")

    # Connect to SQL database
    db_engine = create_engine('mysql+pymysql://root:root@localhost:3308/assignment')  # Update with your database details

    # SQL query to retrieve data
    query = "SELECT * FROM jsondata"  # Update with your table name

    # Load data from SQL
    df = load_data_from_sql(db_engine, query)
    
    if df is not None:
        # Remove leading and trailing spaces in all string columns
        df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)
        
        # Handle null values
        df['end_year'].fillna('Unknown', inplace=True)
        df['intensity'].fillna(0, inplace=True)
        df['sector'].fillna('Unknown', inplace=True)
        df['topic'].fillna('Unknown', inplace=True)
        df['insight'].fillna('No Insight', inplace=True)
        df['url'].fillna('No URL', inplace=True)
        df['region'].fillna('Unknown', inplace=True)
        df['start_year'].fillna('Unknown', inplace=True)
        df['impact'].fillna('No Impact', inplace=True)
        df['country'].fillna('Unknown', inplace=True)
        df['relevance'].fillna(0, inplace=True)
        df['pestle'].fillna('Unknown', inplace=True)
        df['source'].fillna('Unknown', inplace=True)
        df['title'].fillna('No Title', inplace=True)
        df['likelihood'].fillna(0, inplace=True)

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

                st.subheader("Summary Statistics")
                st.write(df_filtered.describe())
                
                # Visualizations
                st.subheader("Visualizations")
                
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
                
                # Heatmap
                st.write("### Heatmap of Intensity by Region and Sector")
                heatmap_data = df_filtered.pivot_table(index='region', columns='sector', values='intensity', aggfunc='mean')
                fig = px.imshow(heatmap_data, title='Heatmap of Intensity by Region and Sector')
                st.plotly_chart(fig)
                
                # Bubble Plot
                st.write("### Intensity vs Likelihood")
                fig = px.scatter(df_filtered, x="intensity", y="likelihood", size="relevance", color="country", title='Bubble Plot of Intensity vs Likelihood')
                st.plotly_chart(fig)


# Main function for Streamlit app
def main():
    st.set_page_config(page_title="Energy Data Analysis", page_icon=":bar_chart:", layout="wide")

    # Create SQLite database connection
    db_conn = sqlite3.connect('users.db')

    # Create users table if not exists
    cursor = db_conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    db_conn.commit()

    # Show login or sign-up page if not logged in
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False

    if st.session_state['logged_in']:
        show_analysis_page()
    else:
        page = st.sidebar.selectbox("Select Page", ["Login", "Sign-Up"])

        if page == "Login":
            show_login_page(db_conn)
        elif page == "Sign-Up":
            show_signup_page(db_conn)

if __name__ == "__main__":
    main()






































