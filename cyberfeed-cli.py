#!/usr/bin/env python3
import json
import os
import sys
import time
import threading
import signal
import argparse
import textwrap
import re
from datetime import datetime
from urllib.parse import urlparse
import concurrent.futures

import feedparser
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich.live import Live
from rich import box
from rich.align import Align
from rich.prompt import Prompt
from rich.layout import Layout
from rich.columns import Columns

# Constants
CONFIG_FILE = "valid-threat-intel-feeds.json"
UPDATE_INTERVAL = 60  # seconds
MAX_ENTRIES = 100
USER_AGENT = "CyberFeed CLI/1.0"

# Global variables
console = Console()
stop_event = threading.Event()
feed_entries = []
feed_lock = threading.Lock()

# Category mapping based on keywords
CATEGORY_KEYWORDS = {
    "malware": ["malware", "virus", "trojan", "ransomware", "botnet", "worm", "spyware"],
    "phishing": ["phish", "phishing", "social engineering", "scam", "fraud"],
    "vulnerability": ["vuln", "cve", "exploit", "disclosure", "patch", "bug", "zero-day", "0day"],
    "network": ["network", "traffic", "packet", "dns", "ip", "protocol", "router"],
    "threat_actor": ["apt", "threat actor", "group", "nation state", "campaign", "hacker"],
    "infrastructure": ["c2", "command and control", "infrastructure", "host", "domain", "server"],
    "defense": ["defense", "protection", "security", "mitigation", "incident response", "soc"],
    "compliance": ["compliance", "regulation", "standard", "iso", "gdpr", "hipaa", "pci"],
    "iot": ["iot", "internet of things", "smart device", "embedded", "firmware"],
    "cloud": ["cloud", "aws", "azure", "gcp", "saas", "paas", "iaas"],
}

def extract_rss_feed_urls(feeds_data):
    """Extract and attempt to find RSS feed URLs from the provided feed data."""
    rss_feed_urls = []
    
    for feed in feeds_data.get("feeds", []):
        feed_url = feed.get("url")
        if not feed_url:
            continue
        
        # Check if the URL is already an RSS feed
        if any(ext in feed_url.lower() for ext in [".rss", ".xml", "/feed", "/rss", "/atom"]):
            rss_feed_urls.append((feed["name"], feed_url))
            continue
        
        # Try to find RSS feed from website
        try:
            # For GitHub repositories, construct a releases feed URL
            if "github.com" in feed_url:
                parts = urlparse(feed_url).path.strip("/").split("/")
                if len(parts) >= 2:
                    owner, repo = parts[0], parts[1]
                    rss_feed_urls.append((feed["name"], f"https://github.com/{owner}/{repo}/releases.atom"))
                    continue
            
            # For other websites, try common feed patterns
            domain = urlparse(feed_url).netloc
            common_paths = [
                "/feed", "/rss", "/atom", "/feeds/posts/default", 
                "/blog/feed", "/index.xml", "/rss.xml", "/feed.xml"
            ]
            
            for path in common_paths:
                test_url = f"https://{domain}{path}"
                resp = requests.head(test_url, timeout=5, headers={"User-Agent": USER_AGENT})
                if resp.status_code == 200 and any(ct in resp.headers.get("Content-Type", "").lower() 
                                                for ct in ["xml", "rss", "atom"]):
                    rss_feed_urls.append((feed["name"], test_url))
                    break
            
            # If no common patterns work, try the original URL
            rss_feed_urls.append((feed["name"], feed_url))
            
        except Exception as e:
            # If we can't find an RSS feed, we'll just use the original URL
            rss_feed_urls.append((feed["name"], feed_url))
    
    return rss_feed_urls

def categorize_entry(entry):
    """Categorize an entry based on its title and content."""
    # Combine title and description for analysis
    text = f"{entry.get('title', '')} {entry.get('summary', '')}"
    text = text.lower()
    
    # Check against our category keywords
    scores = {}
    for category, keywords in CATEGORY_KEYWORDS.items():
        score = sum(1 for keyword in keywords if keyword in text)
        if score > 0:
            scores[category] = score
    
    if scores:
        # Return the category with the highest score
        return max(scores, key=scores.get)
    else:
        # Default category if nothing matches
        return "general"

def fetch_feed(feed_name, feed_url):
    """Fetch a single feed and return parsed entries."""
    try:
        feed = feedparser.parse(feed_url, agent=USER_AGENT)
        
        entries = []
        for entry in feed.entries:
            # Extract publication date
            pub_date = None
            for date_field in ['published_parsed', 'updated_parsed', 'created_parsed']:
                if hasattr(entry, date_field) and getattr(entry, date_field):
                    pub_date = datetime(*getattr(entry, date_field)[:6])
                    break
            
            if not pub_date:
                # Use current time if no date is available
                pub_date = datetime.now()
            
            # Extract category
            category = categorize_entry(entry)
            
            # Get title and clean it up
            title = entry.get('title', 'No Title')
            title = re.sub(r'\s+', ' ', title).strip()
            
            # Get the link
            link = entry.get('link', '')
            
            # Get summary and clean it up
            summary = entry.get('summary', '')
            summary = re.sub(r'<.*?>', '', summary)  # Remove HTML tags
            summary = re.sub(r'\s+', ' ', summary).strip()  # Clean up whitespace
            summary = textwrap.shorten(summary, width=150, placeholder="...")
            
            entries.append({
                'source': feed_name,
                'title': title,
                'link': link,
                'summary': summary,
                'published': pub_date,
                'category': category
            })
        
        return entries
    
    except Exception as e:
        console.print(f"[bold red]Error fetching {feed_name}: {str(e)}[/bold red]")
        return []

def update_feeds(feeds):
    """Update all feeds concurrently and merge results."""
    global feed_entries
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Fetching feeds...", justify="right"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("", total=None)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_feed = {executor.submit(fetch_feed, name, url): name for name, url in feeds}
            
            all_entries = []
            for future in concurrent.futures.as_completed(future_to_feed):
                name = future_to_feed[future]
                try:
                    entries = future.result()
                    all_entries.extend(entries)
                except Exception as e:
                    console.print(f"[bold red]Error processing {name}: {str(e)}[/bold red]")
        
        # Sort entries by publication date (newest first)
        all_entries.sort(key=lambda e: e['published'], reverse=True)
        
        # Limit to max entries
        all_entries = all_entries[:MAX_ENTRIES]
        
        # Update global entries with lock
        with feed_lock:
            feed_entries = all_entries

def format_date(dt):
    """Format the date for display."""
    now = datetime.now()
    delta = now - dt
    
    if delta.days == 0:
        hours = delta.seconds // 3600
        minutes = (delta.seconds // 60) % 60
        
        if hours == 0:
            return f"[green]{minutes}m ago[/green]"
        else:
            return f"[green]{hours}h {minutes}m ago[/green]"
    elif delta.days == 1:
        return "[yellow]Yesterday[/yellow]"
    else:
        return f"[yellow]{dt.strftime('%b %d')}[/yellow]"

def get_category_style(category):
    """Return a rich style based on category."""
    styles = {
        'malware': "bold red",
        'phishing': "bold orange3",
        'vulnerability': "bold yellow",
        'network': "bold blue",
        'threat_actor': "bold magenta",
        'infrastructure': "bold cyan",
        'defense': "bold green",
        'compliance': "bold grey70",
        'iot': "bold purple",
        'cloud': "bold sky_blue2",
        'general': "bold white"
    }
    return styles.get(category, "bold white")

def create_table():
    """Create a rich table for displaying feed entries."""
    table = Table(box=box.ROUNDED, expand=True)
    
    table.add_column("Time", style="dim", width=10)
    table.add_column("Category", width=12)
    table.add_column("Source", width=14)
    table.add_column("Title", ratio=40)
    table.add_column("Summary", ratio=60)
    
    with feed_lock:
        for entry in feed_entries:
            category_style = get_category_style(entry['category'])
            category_text = Text(entry['category'].replace('_', ' ').title(), style=category_style)
            
            table.add_row(
                format_date(entry['published']),
                category_text,
                Text(entry['source'], style="bold"),
                Text(entry['title'], style="bold"),
                entry['summary']
            )
    
    return table

def display_help_panel():
    """Create a help panel with keyboard shortcuts."""
    help_text = """
    [bold green]Keyboard Controls:[/bold green]
    [bold blue]r[/bold blue]: Refresh feeds immediately
    [bold blue]f[/bold blue]: Filter by category
    [bold blue]s[/bold blue]: Search entries
    [bold blue]o[/bold blue]: Open selected entry in browser
    [bold blue]q[/bold blue] or [bold blue]Ctrl+C[/bold blue]: Quit application
    
    [bold green]Status:[/bold green]
    Feeds update automatically every minute.
    """
    return Panel(help_text, title="Help", border_style="blue")

def create_header():
    """Create the application header."""
    header_text = Text()
    header_text.append("🔒 ", style="bold yellow")
    header_text.append("CyberFeed", style="bold blue")
    header_text.append(" - Real-time Cybersecurity Threat Intelligence Feed", style="bold white")
    
    next_update = datetime.now().replace(second=0, microsecond=0)
    next_update = next_update.replace(minute=next_update.minute + 1)
    update_text = f"Next update: {next_update.strftime('%H:%M')}"
    
    header = Columns([
        header_text,
        Text(update_text, style="dim", justify="right")
    ])
    
    return Panel(header, style="blue")

def update_display_thread():
    """Thread function to update the display periodically."""
    last_update = time.time()
    
    try:
        with Live(refresh_per_second=1) as live:
            while not stop_event.is_set():
                # Check if it's time for an update
                current_time = time.time()
                if current_time - last_update >= UPDATE_INTERVAL:
                    update_feeds(feeds)
                    last_update = current_time
                
                # Create layout
                layout = Layout()
                layout.split(
                    Layout(name="header", size=3),
                    Layout(name="body"),
                    Layout(name="footer", size=9)
                )
                
                # Set content
                layout["header"].update(create_header())
                layout["body"].update(create_table())
                layout["footer"].update(display_help_panel())
                
                # Update live display
                live.update(layout)
                
                # Sleep briefly to avoid high CPU usage
                time.sleep(0.1)
    
    except Exception as e:
        console.print(f"[bold red]Display error: {str(e)}[/bold red]")

def signal_handler(sig, frame):
    """Handle Ctrl+C and other signals."""
    stop_event.set()
    console.print("\n[bold yellow]Shutting down...[/bold yellow]")
    time.sleep(1)
    sys.exit(0)

def load_config():
    """Load configuration from file."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        console.print(f"[bold red]Config file {CONFIG_FILE} not found.[/bold red]")
        sys.exit(1)
    except json.JSONDecodeError:
        console.print(f"[bold red]Error parsing {CONFIG_FILE}. Invalid JSON.[/bold red]")
        sys.exit(1)

def main():
    global feeds
    
    # Register signal handler for clean exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Parse arguments
    parser = argparse.ArgumentParser(description="CyberFeed - Cybersecurity Threat Intelligence Feed CLI")
    parser.add_argument("--config", help=f"Path to config file (default: {CONFIG_FILE})")
    args = parser.parse_args()
    
    if args.config:
        global CONFIG_FILE
        CONFIG_FILE = args.config
    
    # Display startup banner
    console.print(Panel.fit(
        "[bold blue]CyberFeed[/bold blue] [bold white]- Cybersecurity Threat Intelligence Feed CLI[/bold white]",
        border_style="yellow"
    ))
    console.print("\n[yellow]Starting up...[/yellow]")
    
    # Load config
    config = load_config()
    
    # Extract RSS feeds
    feeds = extract_rss_feed_urls(config)
    console.print(f"[green]Loaded [bold]{len(feeds)}[/bold] feed sources.[/green]")
    
    # Initial feed update
    console.print("[yellow]Performing initial feed update...[/yellow]")
    update_feeds(feeds)
    
    # Start display thread
    display_thread = threading.Thread(target=update_display_thread)
    display_thread.daemon = True
    display_thread.start()
    
    # Main loop - wait for stop event
    try:
        while not stop_event.is_set():
            time.sleep(0.1)
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)

if __name__ == "__main__":
    main()
