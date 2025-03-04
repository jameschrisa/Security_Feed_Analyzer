# CyberFeed CLI

A modern terminal-based application for monitoring cybersecurity threat intelligence feeds in real-time.

## Features

- Real-time monitoring of cybersecurity RSS feeds
- Automatic categorization of threat intelligence entries
- Color-coded display based on threat categories
- Chronological sorting with newest entries at the top
- Automatic updates every minute
- Clean, modern terminal interface using Rich
- Keyboard shortcuts for easy navigation and control

## Screenshot

```
+-------------------------------------------------------------+
| 🔒 CyberFeed - Real-time Cybersecurity Threat Intelligence  |
+-------------------------------------------------------------+
| Time     | Category   | Source        | Title               |
|----------+------------+---------------+---------------------|
| 2m ago   | Malware    | Feodo Tracker | New Emotet Campaign |
| 15m ago  | Phishing   | PhishTank     | Banking Scam Alert  |
| 1h 5m ago| Vulnerability| ExploitAlert| CVE-2023-XXXX       |
+-------------------------------------------------------------+
| Keyboard Controls:                                          |
| r: Refresh feeds    f: Filter by category    q: Quit        |
+-------------------------------------------------------------+
```

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/cyberfeed-cli.git
   cd cyberfeed-cli
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Make sure the configuration file is in place:
   ```
   cp valid-threat-intel-feeds.json config.json
   ```

## Usage

Run the application:

```
python cyberfeed-cli.py
```

### Command-line arguments

- `--config PATH`: Specify a custom path to the configuration file

### Keyboard shortcuts

- `r`: Refresh feeds immediately
- `f`: Filter entries by category
- `s`: Search entries
- `o`: Open selected entry in browser
- `q` or `Ctrl+C`: Quit application

## Configuration

The application uses a JSON configuration file (`valid-threat-intel-feeds.json`) which contains a list of threat intelligence feeds to monitor. The file should have the following structure:

```json
{
  "feeds": [
    {
      "name": "Feed Name",
      "url": "https://example.com/feed",
      "description": "Description of the feed"
    },
    ...
  ]
}
```

## How It Works

1. The application loads the feed URLs from the configuration file
2. RSS/Atom feeds are extracted from the provided URLs
3. Feeds are fetched concurrently using multithreading
4. Entries are parsed, categorized, and sorted by publication date
5. The terminal display updates every minute with the latest information
6. Content is automatically categorized based on keywords in the title and description

## Categories

Entries are automatically categorized based on keywords:

- **Malware**: Viruses, trojans, ransomware, and other malicious software
- **Phishing**: Social engineering, scams, and fraud attempts
- **Vulnerability**: CVEs, exploits, patches, and zero-days
- **Network**: Traffic analysis, DNS, IP-based threats
- **Threat Actor**: APT groups, campaigns, nation-state actors
- **Infrastructure**: Command and control servers, malicious domains
- **Defense**: Security controls, incident response, mitigation
- **Compliance**: Regulations, standards, frameworks
- **IoT**: Internet of Things security issues
- **Cloud**: Cloud platform vulnerabilities and threats
- **General**: Other cybersecurity topics

## Requirements

- Python 3.7+
- Dependencies listed in `requirements.txt`

## License

MIT License
