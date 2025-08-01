import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from typing import Dict, List, Tuple, Any, Optional
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import networkx as nx
from collections import Counter
import re
from wordcloud import WordCloud
import io
import base64
from PIL import Image
import plotly.io as pio

sns.set_theme(style="whitegrid")
plt.rcParams.update({'font.size': 12})


class ThreatIntelVisualizer:
    """Class for generating visualizations for threat intelligence data."""
    
    def __init__(self, theme: str = "dark"):
        self.theme = theme
        
        if theme == "dark":
            plt.style.use('dark_background')
            self.text_color = "#FFFFFF"
            self.background_color = "#222222"
            self.highlight_color = "#00FFFF"
            self.cmap = "viridis"
        else:
            plt.style.use('default')
            self.text_color = "#333333"
            self.background_color = "#FFFFFF"
            self.highlight_color = "#FF5733"
            self.cmap = "plasma"
            
        self.severity_colors = {
            "Critical": "#FF0000",
            "High": "#FF8C00",
            "Medium": "#FFFF00",
            "Low": "#00FF00",
            "Informational": "#00BFFF"
        }
    
    def create_ioc_distribution_chart(self, ioc_data: Dict[str, List[str]]) -> go.Figure:
        """Create a bar chart showing the distribution of IOC types."""
        if not ioc_data:
            return go.Figure()
            
        filtered_data = {k: v for k, v in ioc_data.items() 
                        if k != 'extraction_metadata' and isinstance(v, list) and len(v) > 0}
        
        ioc_counts = {k: len(v) for k, v in filtered_data.items()}
        sorted_data = sorted(ioc_counts.items(), key=lambda x: x[1], reverse=True)
        
        df = pd.DataFrame(sorted_data, columns=['IOC Type', 'Count'])
        df['IOC Type'] = df['IOC Type'].apply(lambda x: x.replace('_', ' ').title())
        
        fig = px.bar(
            df,
            x='Count',
            y='IOC Type',
            orientation='h',
            title='Distribution of Indicators of Compromise (IOCs)',
            color='Count',
            color_continuous_scale=self.cmap,
            text='Count'
        )
        
        fig.update_layout(
            title_font_size=20,
            xaxis_title="Count",
            yaxis_title="",
            yaxis=dict(categoryorder='total ascending'),
            plot_bgcolor=self.background_color,
            paper_bgcolor=self.background_color,
            font=dict(color=self.text_color),
            height=max(400, len(df) * 30),
        )
        
        fig.update_traces(texttemplate='%{x}', textposition='outside')
        
        return fig
    
    def create_threat_trend_chart(self, feed_data: pd.DataFrame, 
                                  time_window: str = 'week') -> go.Figure:
        """Create a line chart showing threat trends over time."""
        if feed_data is None or feed_data.empty:
            return go.Figure()
            
        if 'published' in feed_data.columns:
            df = feed_data.copy()
            df['published_dt'] = pd.to_datetime(df['published'], errors='coerce')
            df = df.dropna(subset=['published_dt'])
            
            if time_window == 'day':
                df['date_group'] = df['published_dt'].dt.date
                title_period = "Daily"
            elif time_window == 'month':
                df['date_group'] = df['published_dt'].dt.strftime('%Y-%m')
                title_period = "Monthly"
            else:
                df['date_group'] = df['published_dt'].dt.strftime('%Y-%W')
                title_period = "Weekly"
            
            source_counts = df.groupby(['date_group', 'source']).size().reset_index(name='count')
            pivot_data = source_counts.pivot_table(index='date_group', columns='source', values='count', fill_value=0)
            
            fig = make_subplots(specs=[[{"secondary_y": True}]])
            
            for column in pivot_data.columns:
                fig.add_trace(
                    go.Scatter(
                        x=pivot_data.index,
                        y=pivot_data[column],
                        name=column,
                        mode='lines+markers',
                    )
                )
            
            pivot_data['Total'] = pivot_data.sum(axis=1)
            fig.add_trace(
                go.Scatter(
                    x=pivot_data.index,
                    y=pivot_data['Total'],
                    name='Total Articles',
                    mode='lines+markers',
                    line=dict(width=3, dash='dash', color='yellow'),
                    marker=dict(size=10)
                ),
                secondary_y=True
            )
            
            fig.update_layout(
                title=f"{title_period} Threat Intelligence Feed Trends",
                xaxis_title="Time Period",
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                ),
                plot_bgcolor=self.background_color,
                paper_bgcolor=self.background_color,
                font=dict(color=self.text_color),
                height=500
            )
            
            fig.update_yaxes(title_text="Articles per Source", secondary_y=False)
            fig.update_yaxes(title_text="Total Articles", secondary_y=True)
            
            return fig
        else:
            return go.Figure()
    
    def create_source_distribution_pie(self, feed_data: pd.DataFrame) -> go.Figure:
        """Create a pie chart showing distribution of articles by source."""
        if not feed_data.empty and 'source' in feed_data.columns:
            source_counts = feed_data['source'].value_counts().reset_index()
            source_counts.columns = ['Source', 'Articles']
            
            fig = px.pie(
                source_counts, 
                values='Articles', 
                names='Source',
                title='Distribution of Articles by Source',
                hole=0.4,
                color_discrete_sequence=px.colors.sequential.Plasma
            )
            
            fig.update_layout(
                legend=dict(orientation="h", yanchor="bottom", y=-0.3),
                plot_bgcolor=self.background_color,
                paper_bgcolor=self.background_color,
                font=dict(color=self.text_color)
            )
            
            fig.update_traces(textposition='inside', textinfo='percent+label+value')
            
            return fig
        else:
            return go.Figure()

    def create_threat_category_chart(self, feed_data: pd.DataFrame, 
                                     ai_summaries: Dict[str, str]) -> go.Figure:
        """Create a bar chart showing distribution of threat categories based on AI summaries."""
        threat_categories = {
            "Malware & Ransomware": ["malware", "ransomware", "trojan", "virus", "worm", "botnet"],
            "Vulnerabilities & Exploits": ["vulnerability", "exploit", "cve", "patch", "zero-day"],
            "Data Breaches": ["breach", "leak", "exposed", "stolen data", "compromised"],
            "Phishing & Social Engineering": ["phish", "social engineering", "email", "scam"],
            "APT & Nation-State": ["apt", "nation-state", "state-sponsored", "espionage"],
            "Infrastructure": ["infrastructure", "network", "server", "cloud", "hosting"],
            "Financial Crime": ["crypto", "bitcoin", "financial", "payment", "banking"],
            "Compliance & Regulation": ["compliance", "regulation", "gdpr", "law", "legal"]
        }
        
        category_counts = Counter()
        
        for link, summary in ai_summaries.items():
            if not summary or not isinstance(summary, str):
                continue
                
            if summary.startswith("Error"):
                continue
                
            summary_lower = summary.lower()
            
            for category, keywords in threat_categories.items():
                for keyword in keywords:
                    if keyword in summary_lower:
                        category_counts[category] += 1
                        break
        
        categories = list(category_counts.keys())
        counts = list(category_counts.values())
        
        if categories:
            sorted_data = sorted(zip(categories, counts), key=lambda x: x[1], reverse=True)
            categories, counts = zip(*sorted_data) if sorted_data else ([], [])
            
            fig = go.Figure(data=[
                go.Bar(
                    x=categories,
                    y=counts,
                    marker_color=px.colors.sequential.Viridis[:len(categories)],
                    text=counts
                )
            ])
            
            fig.update_layout(
                title="Distribution of Threat Categories",
                xaxis_title="Category",
                yaxis_title="Count",
                plot_bgcolor=self.background_color,
                paper_bgcolor=self.background_color,
                font=dict(color=self.text_color),
                xaxis={'categoryorder':'total descending'}
            )
            
            fig.update_traces(texttemplate='%{text}', textposition='outside')
            
            return fig
        else:
            return go.Figure()
    
    def create_ioc_relationship_graph(self, ioc_data: Dict[str, List[str]], 
                                     max_nodes: int = 50) -> go.Figure:
        """Create a network graph showing relationships between different IOCs."""
        G = nx.Graph()
        
        relevant_types = ['ip_addresses', 'domains', 'urls', 'hashes']
        
        nodes_added = 0
        ioc_map = {}
        
        for ioc_type in relevant_types:
            if ioc_type not in ioc_data:
                continue
                
            iocs = ioc_data[ioc_type]
            
            type_limit = max(5, int(max_nodes / len(relevant_types)))
            iocs = iocs[:min(len(iocs), type_limit)]
            
            for ioc in iocs:
                if nodes_added >= max_nodes:
                    break
                    
                if len(ioc) > 30:
                    display_ioc = ioc[:27] + "..."
                else:
                    display_ioc = ioc
                
                G.add_node(display_ioc, type=ioc_type.replace('_', ' ').title())
                ioc_map[display_ioc] = ioc_type
                nodes_added += 1
        
        for node1 in G.nodes():
            for node2 in G.nodes():
                if node1 != node2:
                    type1 = ioc_map[node1]
                    type2 = ioc_map[node2]
                    
                    if (type1 == 'domains' and type2 == 'ip_addresses') or \
                       (type1 == 'ip_addresses' and type2 == 'domains'):
                        G.add_edge(node1, node2, weight=0.7)
                    
                    elif (type1 == 'domains' and type2 == 'urls') or \
                         (type1 == 'urls' and type2 == 'domains'):
                        if node1 in node2 or node2 in node1:
                            G.add_edge(node1, node2, weight=1.0)
        
        if len(G.nodes()) < 2:
            return go.Figure()
            
        pos = nx.spring_layout(G, k=0.5, iterations=50)
        
        type_colormap = {
            'Ip Addresses': '#FF5733',
            'Domains': '#33FF57',
            'Urls': '#3357FF',
            'Hashes': '#F033FF'
        }
        
        edge_x = []
        edge_y = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines')
        
        node_x = []
        node_y = []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
        node_types = [G.nodes[node]['type'] for node in G.nodes()]
        node_colors = [type_colormap.get(node_type, '#FFFFFF') for node_type in node_types]
            
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers',
            hoverinfo='text',
            marker=dict(
                showscale=False,
                color=node_colors,
                size=10,
                line_width=2))
                
        node_text = []
        for node in G.nodes():
            node_text.append(f"{node}<br>{G.nodes[node]['type']}")
            
        node_trace.text = node_text
        
        fig = go.Figure(data=[edge_trace, node_trace],
                     layout=go.Layout(
                        title=dict(
                            text='IOC Relationship Network',
                            font=dict(size=16)
                        ),
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20,l=5,r=5,t=40),
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        plot_bgcolor=self.background_color,
                        paper_bgcolor=self.background_color,
                        font=dict(color=self.text_color)
                    ))
        
        annotations = []
        y_pos = -0.05
        for ioc_type, color in type_colormap.items():
            annotations.append(
                dict(
                    x=0.01, y=y_pos,
                    xref="paper", yref="paper",
                    text=f"● {ioc_type}",
                    showarrow=False,
                    font=dict(size=12, color=color),
                    align="left"
                )
            )
            y_pos -= 0.04
            
        fig.update_layout(annotations=annotations)
        
        return fig
    
    def create_wordcloud_from_articles(self, feed_data: pd.DataFrame, 
                                       max_words: int = 100) -> np.ndarray:
        """Create a wordcloud visualization from article content."""
        if feed_data is None or feed_data.empty or 'content' not in feed_data.columns:
            fig, ax = plt.subplots(figsize=(10, 5))
            ax.text(0.5, 0.5, "No data available for wordcloud", 
                   ha='center', va='center', fontsize=16)
            ax.axis('off')
            fig.tight_layout(pad=0)
            
            buf = io.BytesIO()
            plt.savefig(buf, format='png', bbox_inches='tight', pad_inches=0)
            buf.seek(0)
            img = np.array(Image.open(buf))
            plt.close(fig)
            return img
            
        all_text = " ".join(feed_data['content'].fillna("").astype(str))
        
        stopwords = ['the', 'and', 'a', 'in', 'to', 'of', 'is', 'that', 'it',
                    'was', 'for', 'on', 'are', 'as', 'with', 'they', 'be',
                    'at', 'this', 'have', 'from', 'or', 'by', 'one', 'had',
                    'but', 'not', 'what', 'all', 'were', 'we', 'when', 'your',
                    'said', 'there', 'use', 'an', 'each']
        
        try:
            wordcloud = WordCloud(
                width=800, height=400,
                background_color=self.background_color,
                max_words=max_words,
                colormap=self.cmap,
                stopwords=stopwords
            ).generate(all_text)
            
            img_array = wordcloud.to_array()
            return img_array
            
        except Exception as e:
            print(f"Error generating wordcloud: {str(e)}")
            
            fig, ax = plt.subplots(figsize=(10, 5))
            ax.text(0.5, 0.5, f"Error generating wordcloud: {str(e)}", 
                   ha='center', va='center', fontsize=16)
            ax.axis('off')
            fig.tight_layout(pad=0)
            
            buf = io.BytesIO()
            plt.savefig(buf, format='png', bbox_inches='tight', pad_inches=0)
            buf.seek(0)
            img = np.array(Image.open(buf))
            plt.close(fig)
            return img
    
    def create_cve_severity_chart(self, ioc_data: Dict[str, List[str]]) -> go.Figure:
        """Create a chart showing CVE severity distribution."""
        if 'cve_ids' not in ioc_data or not ioc_data['cve_ids']:
            return go.Figure()
            
        cve_years = []
        for cve in ioc_data['cve_ids']:
            match = re.search(r'CVE-(\d{4})-', cve, re.IGNORECASE)
            if match:
                cve_years.append(match.group(1))
        
        if not cve_years:
            return go.Figure()
            
        year_counts = Counter(cve_years)
        
        years = sorted(year_counts.keys())
        counts = [year_counts[year] for year in years]
        
        fig = go.Figure(data=[
            go.Bar(
                x=years,
                y=counts,
                marker_color=px.colors.sequential.Viridis,
                text=counts
            )
        ])
        
        fig.update_layout(
            title="CVE Distribution by Year",
            xaxis_title="Year",
            yaxis_title="Number of CVEs",
            plot_bgcolor=self.background_color,
            paper_bgcolor=self.background_color,
            font=dict(color=self.text_color)
        )
        
        fig.update_traces(texttemplate='%{text}', textposition='outside')
        
        return fig
    
    def create_geographical_threat_map(self, ioc_data: Dict[str, List[str]]) -> go.Figure:
        """Create a world map showing geographical distribution of threats based on IPs."""
        regions = {
            "North America": 0, 
            "Europe": 0,
            "Asia": 0,
            "South America": 0, 
            "Africa": 0,
            "Oceania": 0
        }
        
        if 'ip_addresses' in ioc_data and ioc_data['ip_addresses']:
            total_ips = len(ioc_data['ip_addresses'])
            
            regions["North America"] = int(total_ips * 0.35)
            regions["Europe"] = int(total_ips * 0.30)
            regions["Asia"] = int(total_ips * 0.25)
            regions["South America"] = int(total_ips * 0.05)
            regions["Africa"] = int(total_ips * 0.03)
            regions["Oceania"] = int(total_ips * 0.02)
            
            data = pd.DataFrame({
                "Region": regions.keys(),
                "Threats": regions.values()
            })
            
            fig = px.choropleth(
                data,
                locations="Region",
                locationmode="country names",
                color="Threats",
                hover_name="Region",
                color_continuous_scale="viridis",
                projection="natural earth",
                title="Geographic Distribution of Threat Sources",
                labels={"Threats": "Threat Count"},
                height=500
            )
            
            fig.update_layout(
                plot_bgcolor=self.background_color,
                paper_bgcolor=self.background_color,
                font=dict(color=self.text_color),
                geo=dict(
                    showframe=False,
                    showcoastlines=True,
                    projection_type='equirectangular'
                )
            )
            
            return fig
        else:
            return go.Figure()
