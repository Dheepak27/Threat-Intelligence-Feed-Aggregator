import gradio as gr
import pandas as pd
import json
import os
from datetime import datetime
from typing import Dict, List, Tuple, Any
import threading
import time
import plotly.graph_objects as go
import numpy as np
import matplotlib.pyplot as plt
import io
from PIL import Image
import math
# Import our custom modules
from ai_summarizer import AISummarizer
from ioc_extractor import EnhancedIOCExtractor, IOCResult
from visualization_utils import ThreatIntelVisualizer

# Import the original functions we need from app.py
import feedparser
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from dateutil import parser

class ThreatIntelligenceAggregator:
    """
    Main class for the Threat Intelligence Feed Aggregator with Gradio interface.
    Replaces the Streamlit implementation to meet technical expectations.
    """
   
    def __init__(self):
        """Initialize the aggregator with all necessary components."""
        self.feed_sources = [
            {'name': 'The Hacker News', 'url': 'https://feeds.feedburner.com/TheHackersNews'},
            {'name': 'Krebs on Security', 'url': 'https://krebsonsecurity.com/feed/'},
            {'name': 'Bleeping Computer', 'url': 'https://www.bleepingcomputer.com/feed/'},
            {'name': 'Dark Reading', 'url': 'https://www.darkreading.com/rss.xml'},
            {'name': 'Threatpost', 'url': 'https://threatpost.com/feed/'},
            {'name': 'US-CERT', 'url': 'https://us-cert.cisa.gov/ncas/alerts.xml'}
        ]
       
        # Initialize AI summarizer with Ollama support
        self.ai_summarizer = AISummarizer(use_ollama=True)  # Enable Ollama
       
        # Initialize enhanced IOC extractor
        self.ioc_extractor = EnhancedIOCExtractor()
        
        # Initialize visualizer with error handling
        try:
            self.visualizer = ThreatIntelVisualizer(theme="dark")
        except Exception as e:
            print(f"Error initializing visualizer: {str(e)}")
            self.visualizer = None
       
        # Data storage
        self.feed_data = pd.DataFrame()
        self.extracted_iocs = {}
        self.ai_summaries = {}
        self.last_update_time = None
       
        # Threading lock for concurrent operations
        self.update_lock = threading.Lock()
   
    def fetch_rss_feeds(self, progress_callback=None) -> Tuple[pd.DataFrame, str]:
        """
        Fetch and parse RSS feeds with progress updates for Gradio.
       
        Args:
            progress_callback: Optional callback for progress updates
           
        Returns:
            Tuple of (DataFrame with feed data, status message)
        """
        feed_entries = []
        failed_sources = []
       
        total_sources = len(self.feed_sources)
       
        for idx, source in enumerate(self.feed_sources):
            try:
                if progress_callback:
                    progress = (idx + 1) / total_sources
                    progress_callback(progress, f'Fetching from {source["name"]}...')
               
                # Add timeout and user agent for better compatibility
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
               
                # Fetch with timeout
                response = requests.get(source['url'], headers=headers, timeout=10)
                response.raise_for_status()
               
                feed = feedparser.parse(response.content)
               
                for entry in feed.entries:
                    # Extract content from different feed formats
                    content = ""
                    if hasattr(entry, 'content') and entry.content:
                        content = entry.content[0].value if isinstance(entry.content, list) else entry.content
                    elif hasattr(entry, 'summary') and entry.summary:
                        content = entry.summary
                    elif hasattr(entry, 'description') and entry.description:
                        content = entry.description
                           
                    # Extract and format publication date
                    published = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    if hasattr(entry, 'published') and entry.published:
                        try:
                            published = parser.parse(entry.published).strftime('%Y-%m-%d %H:%M:%S')
                        except Exception:
                            pass
                    elif hasattr(entry, 'updated') and entry.updated:
                        try:
                            published = parser.parse(entry.updated).strftime('%Y-%m-%d %H:%M:%S')
                        except Exception:
                            pass
                   
                    # Clean content by removing HTML tags
                    soup = BeautifulSoup(content, 'html.parser')
                    clean_content = soup.get_text(strip=True)
                   
                    # Create feed entry
                    feed_entry = {
                        'title': getattr(entry, 'title', 'No Title'),
                        'link': getattr(entry, 'link', ''),
                        'published': published,
                        'summary': clean_content[:300] + '...' if len(clean_content) > 300 else clean_content,
                        'source': source['name'],
                        'content': clean_content
                    }
                    feed_entries.append(feed_entry)
                       
            except requests.exceptions.RequestException as e:
                failed_sources.append(f"{source['name']}: Network error - {str(e)}")
                continue
            except Exception as e:
                failed_sources.append(f"{source['name']}: {str(e)}")
                continue
       
        df = pd.DataFrame(feed_entries)
       
        # Sort by publication date (newest first)
        if not df.empty and 'published' in df.columns:
            try:
                df['published_dt'] = pd.to_datetime(df['published'], errors='coerce')
                df = df.sort_values(by='published_dt', ascending=False, na_position='last')
                df = df.drop('published_dt', axis=1)
            except Exception as e:
                pass
       
        # Create status message
        status_msg = f"✅ Successfully fetched {len(feed_entries)} articles from {len(self.feed_sources)} sources."
        if failed_sources:
            status_msg += f"\n⚠️ Failed sources: {', '.join(failed_sources[:3])}"
            if len(failed_sources) > 3:
                status_msg += f" and {len(failed_sources) - 3} more"
       
        return df, status_msg
   
    def extract_all_iocs(self, df: pd.DataFrame) -> Dict[str, List[str]]:
        """
        Extract IOCs from all articles using the enhanced extractor.
       
        Args:
            df: DataFrame containing feed data
           
        Returns:
            Dictionary containing all extracted IOCs
        """
        all_iocs_result = IOCResult()
       
        for _, row in df.iterrows():
            if pd.notna(row['content']):
                article_iocs = self.ioc_extractor.extract_iocs(row['content'])
               
                # Merge IOCs
                for attr_name in all_iocs_result.__dataclass_fields__.keys():
                    # Skip non-list attributes like extraction_metadata
                    if attr_name == 'extraction_metadata':
                        continue
                   
                    current_list = getattr(all_iocs_result, attr_name)
                    new_list = getattr(article_iocs, attr_name, [])
                    current_list.extend(new_list)
       
        # Remove duplicates and convert to dict
        result_dict = {}
        for attr_name in all_iocs_result.__dataclass_fields__.keys():
            ioc_list = getattr(all_iocs_result, attr_name)
            result_dict[attr_name] = list(set(ioc_list)) if ioc_list else []
       
        return result_dict
   
    def generate_ai_summaries(self, df: pd.DataFrame, progress_callback=None) -> Dict[str, str]:
        """
        Generate AI summaries for articles using Ollama.
       
        Args:
            df: DataFrame containing feed data
            progress_callback: Optional callback for progress updates
           
        Returns:
            Dictionary mapping article links to summaries
        """
        summaries = {}
        total_articles = len(df)
       
        for idx, (_, row) in enumerate(df.iterrows()):
            if progress_callback:
                progress = (idx + 1) / total_articles
                progress_callback(progress, f'Processing article {idx + 1}/{total_articles}...')
           
            try:
                summary = self.ai_summarizer.generate_summary(row['title'], row['content'])
                summaries[row['link']] = summary
            except Exception as e:
                summaries[row['link']] = f"Error generating summary: {str(e)}"
       
        return summaries
   
    def refresh_data(self, progress=gr.Progress()) -> Tuple[str, str, str, str]:
        """
        Main function to refresh all data - called by Gradio interface.
       
        Args:
            progress: Gradio progress bar
           
        Returns:
            Tuple of (status_message, feed_summary, ioc_summary, update_time)
        """
        with self.update_lock:
            try:
                # Step 1: Fetch RSS feeds
                progress(0.1, "Fetching RSS feeds...")
                self.feed_data, fetch_status = self.fetch_rss_feeds(
                    lambda p, msg: progress(0.1 + p * 0.3, msg)
                )
               
                if self.feed_data.empty:
                    return "❌ No data fetched from feeds", "", "", ""
               
                # Step 2: Extract IOCs
                progress(0.4, "Extracting IOCs...")
                self.extracted_iocs = self.extract_all_iocs(self.feed_data)
               
                # Step 3: Generate AI summaries
                progress(0.6, "Generating AI summaries...")
                self.ai_summaries = self.generate_ai_summaries(
                    self.feed_data.head(10),  # Limit to first 10 for performance
                    lambda p, msg: progress(0.6 + p * 0.3, msg)
                )
               
                # Step 4: Prepare summaries
                progress(0.9, "Finalizing data...")
                self.last_update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
               
                # Create feed summary
                feed_summary = f"""
📊 **Feed Summary**
- Total Articles: {len(self.feed_data)}
- Sources: {', '.join(self.feed_data['source'].unique())}
- Date Range: {self.feed_data['published'].min()} to {self.feed_data['published'].max()}
"""
               
                # Create IOC summary
                ioc_counts = {k: len(v) for k, v in self.extracted_iocs.items() if v}
                total_iocs = sum(ioc_counts.values())
               
                ioc_summary = f"""
🔍 **IOC Summary (Total: {total_iocs})**
"""
                for ioc_type, count in sorted(ioc_counts.items(), key=lambda x: x[1], reverse=True):
                    if count > 0:
                        display_name = ioc_type.replace('_', ' ').title()
                        ioc_summary += f"- {display_name}: {count}\n"
               
                progress(1.0, "Complete!")
               
                return (
                    f"✅ Data refresh completed at {self.last_update_time}\n{fetch_status}",
                    feed_summary,
                    ioc_summary,
                    f"Last updated: {self.last_update_time}"
                )
               
            except Exception as e:
                return f"❌ Error during data refresh: {str(e)}", "", "", ""
   
    def search_articles(self, query: str, source_filter: str = "All Sources") -> str:
        """
        Search articles based on query and source filter.
    
        Args:
            query: Search query string
            source_filter: Source to filter by
        
        Returns:
            Formatted search results
        """
        if self.feed_data.empty:
            return "⚠️ No data available. Please refresh data first."
    
        # Apply filters
        filtered_data = self.feed_data.copy()
    
        if query.strip():
            mask = (
                filtered_data['title'].str.contains(query, case=False, na=False) |
                filtered_data['content'].str.contains(query, case=False, na=False)
            )
            filtered_data = filtered_data[mask]
    
        if source_filter != "All Sources":
            filtered_data = filtered_data[filtered_data['source'] == source_filter]
    
        if filtered_data.empty:
            return f"🔍 No articles found matching '{query}'"
    
        # Format results with better markdown
        total_results = len(filtered_data)
        results = f"🔍 **Found {total_results} articles matching '{query}'**\n\n"
    
        for idx, (_, row) in enumerate(filtered_data.head(10).iterrows()):  # Limit to 10 results
            title = row['title'] if pd.notna(row['title']) else 'No Title'
            source = row['source'] if pd.notna(row['source']) else 'Unknown Source'
            published = row['published'] if pd.notna(row['published']) else 'Unknown Date'
            summary = row['summary'] if pd.notna(row['summary']) else 'No summary available'
            link = row['link'] if pd.notna(row['link']) else '#'
            
            # Truncate summary if too long
            # if len(summary) > 200:
            #     summary = summary[:200] + "..."
            
            results += f"---\n"
            results += f"### {idx + 1}. {title}\n"
            results += f"**📡 Source:** {source} | **📅 Published:** {published}\n\n"
            results += f"**📄 Summary:** {summary}\n\n"
        
            # Add AI summary if available - with better formatting
            if row['link'] in self.ai_summaries:
                ai_data = self.ai_summaries[row['link']]
                
                # Check if ai_data is a dictionary (parsed) or string (raw)
                if isinstance(ai_data, dict):
                    # Format structured AI summary
                    threat_type = ai_data.get('threat_type', 'Unknown')
                    severity = ai_data.get('severity', 'Unknown')
                    confidence = ai_data.get('confidence', 0)
                    ai_summary_text = ai_data.get('summary', '')
                    
                    # # Truncate AI summary if too long
                    # if ai_summary_text and len(ai_summary_text) > 150:
                    #     ai_summary_text = ai_summary_text[:150] + "..."
                    
                    results += f"**🤖 AI Analysis:**\n"
                    results += f"- **Threat Type:** {threat_type}\n"
                    results += f"- **Severity:** {severity}\n"
                    results += f"- **Confidence:** {confidence:.0%}\n"
                    if ai_summary_text:
                        results += f"- **Analysis:** {ai_summary_text}\n"
                    results += "\n"
                    
                    # Add recommendations if available
                    recommendations = ai_data.get('recommendations', [])
                    if recommendations and len(recommendations) > 0:
                        results += f"**🛡️ Key Recommendations:**\n"
                        # Show only top 3 recommendations to keep it clean
                        for rec in recommendations[:3]:
                            results += f"- {rec}\n"
                        results += "\n"
                        
                else:
                    # Handle raw string AI summaries
                    ai_text = str(ai_data)
                    # if len(ai_text) > 200:
                    #     ai_text = ai_text[:200] + "..."
                    results += f"**🤖 AI Summary:** {ai_text}\n\n"
        
            results += f"**🔗 [Read Full Article]({link})**\n\n"
    
        # Add pagination info if there are more results
        if total_results > 10:
            results += f"*Showing top 10 results out of {total_results} total matches.*\n"
    
        return results


    def search_articles_paginated(self, query: str, source_filter: str = "All Sources", page: int = 1, per_page: int = 10) -> tuple:
        """
        Search articles with pagination support.
    
        Args:
            query: Search query string
            source_filter: Source to filter by
            page: Current page number (1-based)
            per_page: Number of results per page
        
        Returns:
            Tuple of (formatted_results, total_results, total_pages)
        """
        if self.feed_data.empty:
            return "⚠️ No data available. Please refresh data first.", 0, 1
    
        # Apply filters
        filtered_data = self.feed_data.copy()
    
        if query.strip():
            mask = (
                filtered_data['title'].str.contains(query, case=False, na=False) |
                filtered_data['content'].str.contains(query, case=False, na=False)
            )
            filtered_data = filtered_data[mask]
    
        if source_filter != "All Sources":
            filtered_data = filtered_data[filtered_data['source'] == source_filter]
    
        total_results = len(filtered_data)
        
        if total_results == 0:
            return f"🔍 No articles found matching '{query}'", 0, 1
    
        # Calculate pagination
        total_pages = math.ceil(total_results / per_page)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        
        # Get current page data
        page_data = filtered_data.iloc[start_idx:end_idx]
    
        # Format results with better markdown
        results = f"🔍 **Found {total_results} articles matching '{query}'**\n\n"
    
        for idx, (_, row) in enumerate(page_data.iterrows()):
            # Calculate the actual article number (not just page index)
            article_num = start_idx + idx + 1
            
            title = row['title'] if pd.notna(row['title']) else 'No Title'
            source = row['source'] if pd.notna(row['source']) else 'Unknown Source'
            published = row['published'] if pd.notna(row['published']) else 'Unknown Date'
            summary = row['summary'] if pd.notna(row['summary']) else 'No summary available'
            link = row['link'] if pd.notna(row['link']) else '#'
            
            # Truncate summary if too long
            if len(summary) > 200:
                summary = summary[:200] + "..."
            
            results += f"---\n"
            results += f"### {article_num}. {title}\n"
            results += f"**📡 Source:** {source} | **📅 Published:** {published}\n\n"
            results += f"**📄 Summary:** {summary}\n\n"
        
            # Add AI summary if available - with better formatting
            if row['link'] in self.ai_summaries:
                ai_data = self.ai_summaries[row['link']]
                
                # Check if ai_data is a dictionary (parsed) or string (raw)
                if isinstance(ai_data, dict):
                    # Format structured AI summary
                    threat_type = ai_data.get('threat_type', 'Unknown')
                    severity = ai_data.get('severity', 'Unknown')
                    confidence = ai_data.get('confidence', 0)
                    ai_summary_text = ai_data.get('summary', '')
                    
                    # Truncate AI summary if too long
                    if ai_summary_text and len(ai_summary_text) > 150:
                        ai_summary_text = ai_summary_text[:150] + "..."
                    
                    results += f"**🤖 AI Analysis:**\n"
                    results += f"- **Threat Type:** {threat_type}\n"
                    results += f"- **Severity:** {severity}\n"
                    results += f"- **Confidence:** {confidence:.0%}\n"
                    if ai_summary_text:
                        results += f"- **Analysis:** {ai_summary_text}\n"
                    results += "\n"
                    
                    # Add recommendations if available
                    recommendations = ai_data.get('recommendations', [])
                    if recommendations and len(recommendations) > 0:
                        results += f"**🛡️ Key Recommendations:**\n"
                        # Show only top 3 recommendations to keep it clean
                        for rec in recommendations[:3]:
                            results += f"- {rec}\n"
                        results += "\n"
                        
                else:
                    # Handle raw string AI summaries
                    ai_text = str(ai_data)
                    if len(ai_text) > 200:
                        ai_text = ai_text[:200] + "..."
                    results += f"**🤖 AI Summary:** {ai_text}\n\n"
        
            results += f"**🔗 [Read Full Article]({link})**\n\n"
    
        return results, total_results, total_pages

    def get_ioc_details(self, ioc_type: str) -> str:
        """
        Get detailed IOC information for a specific type.
       
        Args:
            ioc_type: Type of IOC to display
           
        Returns:
            Formatted IOC details
        """
        if not self.extracted_iocs:
            return "⚠️ No IOCs available. Please refresh data first."
       
        # Map display names to internal keys
        ioc_type_map = {
            "IP Addresses": "ip_addresses",
            "Domains": "domains",
            "URLs": "urls",
            "File Hashes": "hashes",
            "Email Addresses": "emails",
            "Executable Files": "executable_files",
            "CVE IDs": "cve_ids",
            "Bitcoin Addresses": "bitcoin_addresses",
            "Registry Keys": "registry_keys",
            "File Paths": "file_paths",
            "Ports": "ports",
            "Mutex Names": "mutex_names",
            "User Agents": "user_agents"
        }
       
        internal_key = ioc_type_map.get(ioc_type, ioc_type.lower().replace(' ', '_'))
        iocs = self.extracted_iocs.get(internal_key, [])
       
        if not iocs:
            return f"🔍 No {ioc_type.lower()} found in current data."
       
        result = f"🔍 **{ioc_type} ({len(iocs)} found)**\n\n"
       
        # Show first 50 IOCs to avoid overwhelming the interface
        display_iocs = iocs[:50]
       
        for i, ioc in enumerate(display_iocs, 1):
            result += f"{i:3d}. {ioc}\n"
       
        if len(iocs) > 50:
            result += f"\n... and {len(iocs) - 50} more IOCs\n"
       
        result += f"\n📊 Total {ioc_type}: {len(iocs)}"
       
        return result
   
    def export_iocs(self, export_format: str) -> Tuple[str, str]:
        """
        Export IOCs in the specified format.
       
        Args:
            export_format: Format to export (JSON, CSV, TXT)
           
        Returns:
            Tuple of (file_content, filename)
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
       
        if export_format == "JSON":
            content = json.dumps(self.extracted_iocs, indent=2)
            filename = f"threat_iocs_{timestamp}.json"
       
        elif export_format == "CSV":
            # Create CSV format
            csv_lines = ["type,value"]
            for ioc_type, ioc_list in self.extracted_iocs.items():
                for ioc in ioc_list:
                    csv_lines.append(f"{ioc_type},{ioc}")
            content = "\n".join(csv_lines)
            filename = f"threat_iocs_{timestamp}.csv"
       
        else:  # TXT
            txt_lines = []
            for ioc_type, ioc_list in self.extracted_iocs.items():
                if ioc_list:
                    txt_lines.append(f"=== {ioc_type.upper()} ===")
                    txt_lines.extend(ioc_list)
                    txt_lines.append("")
            content = "\n".join(txt_lines)
            filename = f"threat_iocs_{timestamp}.txt"
       
        return content, filename
   
    def add_feed_source(self, name: str, url: str) -> str:
        """
        Add a new feed source.
       
        Args:
            name: Name of the feed source
            url: URL of the RSS/Atom feed
           
        Returns:
            Status message
        """
        if not name.strip() or not url.strip():
            return "❌ Please provide both name and URL"
       
        # Simple URL validation
        if not url.startswith(('http://', 'https://')):
            return "❌ URL must start with http:// or https://"
       
        # Check if already exists
        for source in self.feed_sources:
            if source['url'] == url:
                return f"⚠️ Feed source already exists: {source['name']}"
       
        # Add new source
        self.feed_sources.append({'name': name.strip(), 'url': url.strip()})
       
        return f"✅ Added new feed source: {name}"
   
    def get_feed_sources(self) -> str:
        """Get current feed sources as formatted string."""
        if not self.feed_sources:
            return "No feed sources configured."
       
        result = "📡 **Current Feed Sources:**\n\n"
        for i, source in enumerate(self.feed_sources, 1):
            result += f"{i:2d}. **{source['name']}**\n"
            result += f"    URL: {source['url']}\n\n"
       
        return result
        
    def generate_ioc_distribution_chart(self) -> Any:
        """Generate IOC distribution chart using the visualizer."""
        try:
            if not self.visualizer or not self.extracted_iocs:
                return None
            
            return self.visualizer.create_ioc_distribution_chart(self.extracted_iocs)
        except Exception as e:
            print(f"Error generating IOC distribution chart: {str(e)}")
            return None
        
    def generate_threat_trend_chart(self, time_window: str = 'week') -> Any:
        """Generate threat trend chart using the visualizer."""
        try:
            if not self.visualizer or self.feed_data.empty:
                return None
                
            return self.visualizer.create_threat_trend_chart(self.feed_data, time_window)
        except Exception as e:
            print(f"Error generating threat trend chart: {str(e)}")
            return None
        
    def generate_source_distribution_pie(self) -> Any:
        """Generate source distribution pie chart using the visualizer."""
        try:
            if not self.visualizer or self.feed_data.empty:
                return None
                
            return self.visualizer.create_source_distribution_pie(self.feed_data)
        except Exception as e:
            print(f"Error generating source distribution pie: {str(e)}")
            return None
        
    def generate_threat_category_chart(self) -> Any:
        """Generate threat category chart using the visualizer."""
        try:
            if not self.visualizer or self.feed_data.empty or not self.ai_summaries:
                return None
                
            return self.visualizer.create_threat_category_chart(self.feed_data, self.ai_summaries)
        except Exception as e:
            print(f"Error generating threat category chart: {str(e)}")
            return None
        
    def generate_ioc_relationship_graph(self) -> Any:
        """Generate IOC relationship network graph using the visualizer."""
        try:
            if not self.visualizer or not self.extracted_iocs:
                return None
                
            return self.visualizer.create_ioc_relationship_graph(self.extracted_iocs)
        except Exception as e:
            print(f"Error generating IOC relationship graph: {str(e)}")
            return None
        
    def generate_wordcloud(self) -> np.ndarray:
        """Generate wordcloud from article content using the visualizer."""
        try:
            if not self.visualizer or self.feed_data.empty:
                # Return an empty image
                fig, ax = plt.subplots(figsize=(10, 5))
                ax.text(0.5, 0.5, "No data available for wordcloud", 
                       ha='center', va='center', fontsize=16)
                ax.axis('off')
                fig.tight_layout(pad=0)
                
                # Convert to image array
                buf = io.BytesIO()
                plt.savefig(buf, format='png', bbox_inches='tight', pad_inches=0)
                buf.seek(0)
                img = np.array(Image.open(buf))
                plt.close(fig)
                return img
                
            return self.visualizer.create_wordcloud_from_articles(self.feed_data)
        except Exception as e:
            print(f"Error generating wordcloud: {str(e)}")
            # Return an error image
            fig, ax = plt.subplots(figsize=(10, 5))
            ax.text(0.5, 0.5, f"Error generating wordcloud: {str(e)}", 
                   ha='center', va='center', fontsize=16)
            ax.axis('off')
            fig.tight_layout(pad=0)
            
            # Convert to image array
            buf = io.BytesIO()
            plt.savefig(buf, format='png', bbox_inches='tight', pad_inches=0)
            buf.seek(0)
            img = np.array(Image.open(buf))
            plt.close(fig)
            return img
        
    def generate_cve_severity_chart(self) -> Any:
        """Generate CVE severity chart using the visualizer."""
        try:
            if not self.visualizer or not self.extracted_iocs or 'cve_ids' not in self.extracted_iocs:
                return None
                
            return self.visualizer.create_cve_severity_chart(self.extracted_iocs)
        except Exception as e:
            print(f"Error generating CVE severity chart: {str(e)}")
            return None
        
    def generate_geographical_threat_map(self) -> Any:
        """Generate geographical threat map using the visualizer."""
        try:
            if not self.visualizer or not self.extracted_iocs or 'ip_addresses' not in self.extracted_iocs:
                return None
                
            return self.visualizer.create_geographical_threat_map(self.extracted_iocs)
        except Exception as e:
            print(f"Error generating geographical threat map: {str(e)}")
            return None

def create_gradio_interface():
    """
    Create and configure the Gradio interface for the Threat Intelligence Aggregator.
    This replaces the Streamlit interface to meet technical expectations.
    """
    # Initialize the aggregator
    aggregator = ThreatIntelligenceAggregator()
   
    # Custom CSS for better styling
    css = """
    .gradio-container {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .main-header {
        text-align: center;
        color: #2c3e50;
        margin-bottom: 2rem;
    }
    .status-box {
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    .success {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
    }
    .warning {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        color: #856404;
    }
    .info {
        background-color: #d1ecf1;
        border: 1px solid #bee5eb;
        color: #0c5460;
    }
    """
   
    # Create the main interface
    with gr.Blocks(css=css, title="🛡️ Threat Intelligence Feed Aggregator", theme=gr.themes.Soft()) as interface:
       
        # Header
        gr.Markdown("# 🛡️ Threat Intelligence Feed Aggregator")
        gr.Markdown("*AI-Powered Threat Intelligence Platform with Ollama Integration*")
       
        # Main tabs
        with gr.Tabs():
           
            # Tab 1: Dashboard & Data Refresh
            with gr.TabItem("📊 Dashboard"):
               
                with gr.Row():
                    refresh_btn = gr.Button("🔄 Refresh All Data", variant="primary", size="lg")
               
                # Status and summary displays
                with gr.Row():
                    with gr.Column():
                        status_display = gr.Markdown("ℹ️ Click 'Refresh All Data' to load threat intelligence feeds.")
                   
                with gr.Row():
                    with gr.Column():
                        feed_summary = gr.Markdown("## 📰 Feed Summary\nNo data loaded yet.")
                    with gr.Column():
                        ioc_summary = gr.Markdown("## 🔍 IOC Summary\nNo data loaded yet.")
               
                update_time_display = gr.Markdown("*No updates yet*")
               
                # Connect refresh button
                refresh_btn.click(
                    fn=aggregator.refresh_data,
                    outputs=[status_display, feed_summary, ioc_summary, update_time_display]
                )
                
            # Tab 2: Analytics & Visualizations
            with gr.TabItem("📈 Analytics"):
                gr.Markdown("## 📊 Threat Intelligence Visualizations")
                gr.Markdown("Explore threat intelligence data through interactive visualizations")
                
                # Refresh visualizations button
                with gr.Row():
                    refresh_viz_btn = gr.Button("🔄 Refresh Visualizations", variant="primary")
                
                # Select time window for trend analysis
                time_window = gr.Radio(
                    ["day", "week", "month"],
                    label="Time Window for Trend Analysis",
                    value="week"
                )
                
                # Main visualizations in tabs
                with gr.Tabs():
                    with gr.TabItem("IOC Distribution"):
                        ioc_dist_plot = gr.Plot(label="IOC Distribution")
                        
                    with gr.TabItem("Source Distribution"):
                        source_dist_plot = gr.Plot(label="Source Distribution")
                        
                    with gr.TabItem("Threat Trends"):
                        threat_trend_plot = gr.Plot(label="Threat Trends Over Time")
                        
                    with gr.TabItem("IOC Relationships"):
                        ioc_network_plot = gr.Plot(label="IOC Relationship Network")
                        
                    with gr.TabItem("CVE Analysis"):
                        cve_plot = gr.Plot(label="CVE Analysis")
                        
                    with gr.TabItem("Geographic Distribution"):
                        geo_plot = gr.Plot(label="Geographic Distribution")
                        
                    with gr.TabItem("Topic Analysis"):
                        gr.Markdown("### 🔤 Common Topics in Threat Intelligence")
                        wordcloud_img = gr.Image(label="Topic Wordcloud", show_download_button=False)
                    
                    with gr.TabItem("🌍 Live Threat Map"):
                        gr.Markdown("### 🔴 Real-time Global Threat Map")
                        gr.Markdown("Interactive threat intelligence map powered by Bitdefender")
                        
                        # Iframe for Bitdefender threat map
                        threat_map_iframe = gr.HTML(
                            value="""
                            <iframe src="https://threatmap.bitdefender.com/"
                                    width="100%" height="600"
                                    style="border:none; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);"
                                    allow="geolocation"
                                    sandbox="allow-scripts allow-same-origin">
                            </iframe>
                            """,
                            label="Bitdefender Threat Map"
                        )
                
                # Connect visualization refresh button
                def refresh_all_visualizations(time_period):
                    # Create a default empty figure to use when data is not available
                    empty_fig = go.Figure()
                    empty_fig.update_layout(
                        title="No Data Available",
                        xaxis=dict(visible=False),
                        yaxis=dict(visible=False),
                        annotations=[dict(
                            text="No data is available. Please refresh data first.",
                            showarrow=False,
                            font=dict(size=16)
                        )]
                    )
                    
                    # Get visualization data with safety checks
                    try:
                        ioc_dist = aggregator.generate_ioc_distribution_chart() or empty_fig
                        source_dist = aggregator.generate_source_distribution_pie() or empty_fig
                        threat_trend = aggregator.generate_threat_trend_chart(time_period) or empty_fig
                        ioc_network = aggregator.generate_ioc_relationship_graph() or empty_fig
                        cve_analysis = aggregator.generate_cve_severity_chart() or empty_fig
                        geo_dist = aggregator.generate_geographical_threat_map() or empty_fig
                        try:
                            wordcloud = aggregator.generate_wordcloud()
                        except Exception as e:
                            print(f"Error generating wordcloud: {str(e)}")
                            wordcloud = None
                    except Exception as e:
                        print(f"Error generating visualizations: {str(e)}")
                        return tuple([empty_fig] * 6 + [None])
                    
                    return (
                        ioc_dist,
                        source_dist,
                        threat_trend,
                        ioc_network,
                        cve_analysis,
                        geo_dist,
                        wordcloud
                    )
                
                refresh_viz_btn.click(
                    fn=refresh_all_visualizations,
                    inputs=[time_window],
                    outputs=[
                        ioc_dist_plot,
                        source_dist_plot,
                        threat_trend_plot,
                        ioc_network_plot,
                        cve_plot,
                        geo_plot,
                        wordcloud_img
                    ]
                )
           
            # Tab 3: Search & Browse Articles
            with gr.TabItem("🔍 Search Articles"):
               
                with gr.Row():
                    search_query = gr.Textbox(
                        placeholder="Enter keywords, CVE IDs, domains...",
                        label="🔍 Search Query",
                        scale=3
                    )
                    source_dropdown = gr.Dropdown(
                        choices=["All Sources"] + [source['name'] for source in aggregator.feed_sources],
                        value="All Sources",
                        label="📡 Filter by Source",
                        scale=1
                    )
               
                search_btn = gr.Button("🔍 Search Articles", variant="primary")
                
                # Add pagination controls
                with gr.Row():
                    prev_btn = gr.Button("⬅️ Previous", variant="secondary", scale=1)
                    with gr.Column(scale=2):
                        page_info = gr.Markdown("")
                    next_btn = gr.Button("➡️ Next", variant="secondary", scale=1)

                # Results per page selector
                with gr.Row():
                    results_per_page = gr.Dropdown(
                        choices=[5, 10, 20, 50],
                        value=10,
                        label="Results per page",
                        scale=1
                    )
                    
                search_results = gr.Markdown("Enter a search query to find relevant threat intelligence articles.")
                
                # Store current page state (this will be handled in the backend)
                current_page = gr.State(1)
                total_pages = gr.State(1)
                current_query = gr.State("")
                current_source = gr.State("All Sources")
               
                # Connect search functionality with pagination
                def search_with_pagination(query, source, page, per_page):
                    results, total_results, total_pgs = aggregator.search_articles_paginated(query, source, page, per_page)
                    
                    # Update page info
                    if total_results > 0:
                        start_idx = (page - 1) * per_page + 1
                        end_idx = min(page * per_page, total_results)
                        page_info_text = f"📄 Page {page} of {total_pgs} | Showing {start_idx}-{end_idx} of {total_results} results"
                    else:
                        page_info_text = "No results found"
                        
                    return results, page_info_text, total_pgs, query, source
                
                def go_to_next_page(current_pg, total_pgs, query, source, per_page):
                    if current_pg < total_pgs:
                        new_page = current_pg + 1
                        return search_with_pagination(query, source, new_page, per_page) + (new_page,)
                    return gr.update(), gr.update(), total_pgs, query, source, current_pg
                
                def go_to_prev_page(current_pg, total_pgs, query, source, per_page):
                    if current_pg > 1:
                        new_page = current_pg - 1
                        return search_with_pagination(query, source, new_page, per_page) + (new_page,)
                    return gr.update(), gr.update(), total_pgs, query, source, current_pg
                
                # Search button click
                search_btn.click(
                    fn=search_with_pagination,
                    inputs=[search_query, source_dropdown, gr.State(1), results_per_page],
                    outputs=[search_results, page_info, total_pages, current_query, current_source]
                ).then(
                    fn=lambda: 1,  # Reset to page 1 on new search
                    outputs=current_page
                )
                
                # Next button click
                next_btn.click(
                    fn=go_to_next_page,
                    inputs=[current_page, total_pages, current_query, current_source, results_per_page],
                    outputs=[search_results, page_info, total_pages, current_query, current_source, current_page]
                )
                
                # Previous button click
                prev_btn.click(
                    fn=go_to_prev_page,
                    inputs=[current_page, total_pages, current_query, current_source, results_per_page],
                    outputs=[search_results, page_info, total_pages, current_query, current_source, current_page]
                )
                
                # Results per page change
                results_per_page.change(
                    fn=lambda query, source, per_page: search_with_pagination(query, source, 1, per_page) + (1,),
                    inputs=[current_query, current_source, results_per_page],
                    outputs=[search_results, page_info, total_pages, current_query, current_source, current_page]
                )

            # Keep all your other tabs (Tab 4, 5, 6) exactly as they are
            # Tab 4: IOC Analysis
            with gr.TabItem("🎯 IOC Analysis"):
               
                with gr.Row():
                    ioc_type_dropdown = gr.Dropdown(
                        choices=[
                            "IP Addresses", "Domains", "URLs", "File Hashes",
                            "Email Addresses", "Executable Files", "CVE IDs",
                            "Bitcoin Addresses", "Registry Keys", "File Paths",
                            "Ports", "Mutex Names", "User Agents"
                        ],
                        value="IP Addresses",
                        label="🔍 Select IOC Type",
                        scale=2
                    )
                    view_iocs_btn = gr.Button("📋 View IOCs", variant="primary", scale=1)
               
                ioc_details = gr.Markdown("Select an IOC type and click 'View IOCs' to see extracted indicators.")
               
                # Export section
                gr.Markdown("## 📤 Export IOCs")
                with gr.Row():
                    export_format = gr.Dropdown(
                        choices=["JSON", "CSV", "TXT"],
                        value="JSON",
                        label="Export Format",
                        scale=1
                    )
                    export_btn = gr.Button("📥 Export IOCs", variant="secondary", scale=1)
               
                export_file = gr.File(label="📁 Download Exported IOCs", visible=False)
               
                # Connect IOC functionality
                view_iocs_btn.click(
                    fn=aggregator.get_ioc_details,
                    inputs=ioc_type_dropdown,
                    outputs=ioc_details
                )
               
                def export_iocs_wrapper(format_type):
                    content, filename = aggregator.export_iocs(format_type)
                    # Save to temporary file
                    with open(filename, 'w') as f:
                        f.write(content)
                    return gr.update(value=filename, visible=True)
               
                export_btn.click(
                    fn=export_iocs_wrapper,
                    inputs=export_format,
                    outputs=export_file
                )
           
            # Tab 5: Feed Management
            with gr.TabItem("⚙️ Feed Management"):
               
                # Current sources display
                current_sources = gr.Markdown(aggregator.get_feed_sources())
               
                gr.Markdown("## ➕ Add New Feed Source")
                with gr.Row():
                    new_feed_name = gr.Textbox(
                        placeholder="e.g., Security Blog",
                        label="Feed Name",
                        scale=1
                    )
                    new_feed_url = gr.Textbox(
                        placeholder="https://example.com/feed.xml",
                        label="Feed URL",
                        scale=2
                    )
               
                with gr.Row():
                    add_feed_btn = gr.Button("➕ Add Feed Source", variant="primary")
                    refresh_sources_btn = gr.Button("🔄 Refresh Sources", variant="secondary")
               
                add_feed_status = gr.Markdown("")
               
                # Connect feed management
                add_feed_btn.click(
                    fn=aggregator.add_feed_source,
                    inputs=[new_feed_name, new_feed_url],
                    outputs=add_feed_status
                )
               
                refresh_sources_btn.click(
                    fn=aggregator.get_feed_sources,
                    outputs=current_sources
                )
           
            # Tab 6: System Information
            with gr.TabItem("ℹ️ About"):
               
                gr.Markdown("""
                ## 🛡️ Threat Intelligence Feed Aggregator
               
                **Version:** 2.0 - Gradio Interface
                **Python Compatibility:** 3.13+
               
                ### ✨ Key Features:
                - 🔄 **Real-time RSS/Atom feed aggregation** from multiple threat intelligence sources
                - 🤖 **AI-powered threat summarization** using Ollama with local LLM integration
                - 🔍 **Advanced IOC extraction** with support for 13+ indicator types
                - 📊 **Interactive Gradio dashboard** for security analysts and researchers
                - 📤 **Multiple export formats** (JSON, CSV, TXT) for integration with security tools
                - ⚙️ **Customizable feed sources** for tailored threat monitoring
               
                ### 🎯 Supported IOC Types:
                - IP addresses (with private range filtering)
                - Domain names and URLs
                - File hashes (MD5, SHA1, SHA256, SHA512)
                - Email addresses
                - Executable files and registry keys
                - CVE identifiers
                - Bitcoin addresses
                - Network ports and mutex names
                - User agents and file paths
               
                ### 🧠 AI Integration:
                - **Ollama Integration:** Local LLM processing for privacy-focused analysis
                - **Threat Classification:** Automatic categorization of threats
                - **Actionable Recommendations:** Security-focused response guidance
                - **Context-Aware Analysis:** Enhanced IOC extraction with confidence scoring
               
                ### 🔧 Technical Stack:
                - **Backend:** Python 3.13+ with feedparser, BeautifulSoup, pandas
                - **Frontend:** Gradio for accessible web interface
                - **AI:** Ollama integration for local LLM processing
                - **IOC Extraction:** Advanced regex patterns with validation
                - **Data Processing:** Modular architecture with threading support
               
                ### 📚 Use Cases:
                1. **SOC Teams:** Centralized threat intelligence monitoring
                2. **Security Researchers:** Real-time threat analysis and aggregation
                3. **Incident Response:** Fast identification of new threats and vulnerabilities
                4. **Threat Hunting:** IOC extraction for proactive security measures
                5. **Education:** Learning platform for cybersecurity students
               
                ### 🚀 Getting Started:
                1. Click **"🔄 Refresh All Data"** to load latest threat intelligence
                2. Use **"🔍 Search Articles"** to find specific threats or topics
                3. Explore **"🎯 IOC Analysis"** to extract and export indicators
                4. Manage **"⚙️ Feed Management"** to add custom sources
               
                ---
                *Built for the cybersecurity community with ❤️*
                """)
   
    return interface

# Keep your main function exactly as is
def main():
    """
    Main function to launch the Gradio interface.
    This replaces the Streamlit app.run() call.
    """
    print("🛡️ Starting Threat Intelligence Feed Aggregator...")
    print("📊 Initializing Gradio interface...")
   
    # Create and launch the interface
    interface = create_gradio_interface()
   
    print("🚀 Launching web interface...")
    print("🌐 Access the application at: http://localhost:7860")
   
    # Launch with appropriate settings
    interface.launch(
        server_name="0.0.0.0",  # Allow external access
        server_port=7860,
        # share=True,  # Set to True if you want a public link
        debug=True,  # Enable debug mode
        show_error=True,
        inbrowser=True  # Auto-open browser
    )

if __name__ == "__main__":
    main()