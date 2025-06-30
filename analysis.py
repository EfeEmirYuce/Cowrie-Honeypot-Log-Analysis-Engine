import os
import glob
import json
import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# --- CONFIGURATION ---
LOG_DIRECTORY = 'logs'
# --- END CONFIGURATION ---

# --- ANALYSIS KEYWORDS ---
# We define keywords to categorize commands. Using sets for efficient lookups.
KEYWORDS = {
    'recon': {'whoami', 'uname', 'ls', 'pwd', 'ifconfig', 'ip a', 'netstat', 'ps', 'top', 'history', 'cat /etc/passwd'},
    'download': {'wget', 'curl', 'tftp', 'ftpget'},
    'destructive': {'rm', 'mkfs', 'dd'},
    'persistence': {'crontab', 'systemctl enable', '/etc/init.d'}
}
# --- END KEYWORDS ---

def read_log_files(log_path):
    """
    Reads all 'cowrie*.json' files in the specified directory and
    returns the JSON data as a list of dictionaries.
    """
    file_pattern = os.path.join(log_path, 'cowrie*.json')
    log_files = glob.glob(file_pattern)
    
    if not log_files:
        print(f"No log files found in directory: {log_path}")
        return []

    print(f"Found {len(log_files)} log file(s).")
    
    all_events = []
    for file_path in log_files:
        print(f"Reading file: {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    all_events.append(event)
                except json.JSONDecodeError:
                    print(f"  - Skipped corrupted JSON line in file: {file_path}")
                    continue
                    
    print(f"Total {len(all_events)} events (log lines) read.")
    return all_events

def group_and_filter_sessions(df):
    """
    Filters for command input events and groups them by session ID.
    """
    # We are only interested in commands entered by the attacker.
    # So, we filter the DataFrame for events where 'eventid' is 'cowrie.command.input'.
    command_df = df[df['eventid'] == 'cowrie.command.input'].copy()
    
    # Ensure the 'input' and 'session' columns exist.
    if 'input' not in command_df.columns or 'session' not in command_df.columns:
        print("Error: 'input' or 'session' column not found in logs.")
        return None

    # Group by the 'session' ID and aggregate all commands ('input') into a list.
    # The result is a mapping from each session ID to a list of commands.
    sessions = command_df.groupby('session').agg(
    src_ip=('src_ip', 'first'),
    commands=('input', list)
)
    
    print(f"\nFound {len(sessions)} sessions with command inputs.")
    return sessions

def analyze_session_with_rules(session_id, commands):
    """
    Analyzes a session based on a set of predefined rules and keywords, without using an AI API.
    """
    scores = {
        'recon': 0,
        'download': 0,
        'destructive': 0,
        'persistence': 0
    }
    suspicious_items = []
    
    for command in commands:
        # Check for download tools and extract URLs
        if any(tool in command for tool in KEYWORDS['download']):
            scores['download'] += 1
            # Try to find URLs in the command using a simple regex
            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', command)
            if urls:
                suspicious_items.extend(urls)

        # Check for reconnaissance commands
        if any(tool in command for tool in KEYWORDS['recon']):
            scores['recon'] += 1
            
        # Check for destructive commands
        if any(tool in command for tool in KEYWORDS['destructive']):
            scores['destructive'] += 1
            suspicious_items.append(command) # Add the whole command as suspicious

        # Check for persistence commands
        if any(tool in command for tool in KEYWORDS['persistence']):
            scores['persistence'] += 1
            suspicious_items.append(command)

    # --- Determine Intent and Skill Level based on scores ---
    intent = "Uncategorized"
    if scores['destructive'] > 0:
        intent = "Destructive"
    elif scores['download'] > 0:
        intent = "Malware Deployment"
    elif scores['persistence'] > 0:
        intent = "Persistence Attempt"
    elif scores['recon'] > 0:
        intent = "Reconnaissance"
        
    skill_level = "Low (Script Kiddie)"
    if scores['download'] > 0 and scores['recon'] > 1:
        skill_level = "Medium (Automated Script)"
    elif len(commands) > 10 and scores['recon'] > 5:
        skill_level = "Medium (Manual Exploration)"

    summary = f"Attacker executed {len(commands)} commands, showing signs of {intent}."

    analysis = {
        "intent": intent,
        "skill_level": skill_level,
        "summary": summary,
        "suspicious_items": list(set(suspicious_items)) # Remove duplicates
    }
    
    return analysis

def save_results_to_files(results_df):
    """Saves the analysis results to CSV and HTML files."""
    try:
        # Save to CSV
        results_df.to_csv('ai_analysis_report.csv', index=False, encoding='utf-8-sig')
        print("\n[SUCCESS] Analysis report saved to 'ai_analysis_report.csv'")
        
        # Save to HTML
        results_df.to_html('ai_analysis_report.html', escape=False, index=False)
        print("[SUCCESS] Analysis report saved to 'ai_analysis_report.html'")

    except Exception as e:
        print(f"\n[ERROR] Failed to save report files: {e}")

def create_visualizations(results_df):
    """Creates and saves visualizations based on the analysis results."""
    if results_df.empty:
        print("\nNo data available to create visualizations.")
        return
        
    print("\n--- Creating Visualizations ---")
    
    try:
        # Set the style for the plots
        sns.set_theme(style="whitegrid")

        # 1. Bar Chart for Attack Intent
        plt.figure(figsize=(10, 6))
        sns.countplot(y='intent', data=results_df, order=results_df['intent'].value_counts().index, palette='viridis', hue='intent', legend=False)        
        plt.title('Distribution of Attacker Intents')
        plt.xlabel('Number of Sessions')
        plt.ylabel('Intent')
        plt.tight_layout()
        plt.savefig('attack_intent_distribution.png')
        print("[SUCCESS] Visualization saved to 'attack_intent_distribution.png'")
        plt.close()

        # 2. Pie Chart for Attacker Skill Level
        plt.figure(figsize=(8, 8))
        skill_counts = results_df['skill_level'].value_counts()
        plt.pie(skill_counts, labels=skill_counts.index, autopct='%1.1f%%', startangle=140, colors=sns.color_palette('pastel'))
        plt.title('Distribution of Attacker Skill Levels')
        plt.ylabel('') # Hide the y-label for pie charts
        plt.savefig('attacker_skill_level.png')
        print("[SUCCESS] Visualization saved to 'attacker_skill_level.png'")
        plt.close()

    except Exception as e:
        print(f"[ERROR] Failed to create visualizations: {e}")

# --- Main execution block of the script ---
if __name__ == '__main__':
    events_list = read_log_files(LOG_DIRECTORY)
    
    if events_list:
        df = pd.DataFrame(events_list)
        attacker_sessions = group_and_filter_sessions(df)
        
        if attacker_sessions is not None and not attacker_sessions.empty:
            
            analysis_results = []
            total_sessions_to_analyze = len(attacker_sessions)
            
            print(f"\n--- Starting Rule-Based Analysis ({total_sessions_to_analyze} Sessions) ---")
            
            for i, (session_id, row) in enumerate(attacker_sessions.iterrows()):
                # Extract commands and src_ip from the row
                commands = row['commands']
                src_ip = row['src_ip']
                # Call our new rule-based analysis function
                analysis = analyze_session_with_rules(session_id, commands)
                
                analysis['session_id'] = session_id
                analysis['src_ip'] = src_ip
                analysis['command_count'] = len(commands)
                analysis_results.append(analysis)

            if analysis_results:
                results_df = pd.DataFrame(analysis_results)
                
                cols_order = ['session_id', 'src_ip', 'intent', 'skill_level', 'command_count', 'summary', 'suspicious_items']
                # Ensure all columns exist before reordering
                for col in cols_order:
                    if col not in results_df.columns:
                        results_df[col] = 'N/A' # or pd.NA
                results_df = results_df[cols_order]

                save_results_to_files(results_df)
                create_visualizations(results_df)

                print("\n--- Analysis Complete! ---")
            else:
                print("\nNo sessions were successfully analyzed.")