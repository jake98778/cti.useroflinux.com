import re
import json
import feedparser
import requests
import os
from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date, timedelta
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from bs4 import BeautifulSoup
from flask_caching import Cache

# Set up logging to file and console for better debugging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),  # Log to a file for persistence
        logging.StreamHandler()          # Also print to console
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
DB_PATH = '/home/Jake98778/CTI/var/cve.db'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CACHE_TYPE'] = 'simple'  # In-memory cache
db = SQLAlchemy(app)
cache = Cache(app)

app.jinja_env.filters['from_json'] = json.loads

progress = {'total': 0, 'completed': 0, 'done': False}

class CVE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(13), unique=True, nullable=False)
    description = db.Column(db.String, nullable=True)
    severity = db.Column(db.Float, nullable=True)
    publication_date = db.Column(db.Date, nullable=True)
    news_articles = db.Column(db.String, nullable=True)
    date_imported = db.Column(db.DateTime, default=datetime.utcnow)

class Keyword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    word = db.Column(db.String(50), unique=True, nullable=False)

def init_db():
    db_path = DB_PATH
    db_dir = os.path.dirname(db_path)
    logger.info(f"Checking database at {db_path}")

    if not os.path.exists(db_dir):
        logger.info(f"Directory {db_dir} not found, creating...")
        try:
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f"Created directory {db_dir}")
        except Exception as e:
            logger.error(f"Failed to create directory {db_dir}: {e}")
            raise

    if not os.path.exists(db_path):
        logger.info(f"Database file {db_path} not found, attempting to create...")
        with app.app_context():
            try:
                db.drop_all()
                db.create_all()
                db.session.commit()
                logger.info(f"Database created successfully at {db_path}")
            except Exception as e:
                logger.error(f"Failed to create database: {e}")
                raise Exception(f"Database creation failed: {e}")
    else:
        logger.info(f"Database file {db_path} already exists")

def fetch_cves():
    global progress
    rss_feeds = [
        "https://www.bleepingcomputer.com/feed/",
        "https://www.darkreading.com/rss.xml",
        "https://www.threatpost.com/feed/",
        "https://www.schneier.com/feed/atom/",
        "https://www.krebsonsecurity.com/feed/",
        "https://www.infosecurity-magazine.com/rss/news/",
        "https://news.ycombinator.com/rss",
        "https://www.sentinelone.com/labs/feed/",
        "https://www.zdnet.com/topic/security/rss.xml",
        "https://www.csoonline.com/feed",
        "https://securelist.com/feed/",
        "https://blog.talosintelligence.com/rss/",
        "https://msrc-blog.microsoft.com/feed/",
        "https://blog.qualys.com/feed",
        "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
        "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "https://isc.sans.edu/rssfeed.xml",
        "https://www.zerodayinitiative.com/rss/upcoming/",
        "https://www.zerodayinitiative.com/rss/published/",
        "https://www.zerodayinitiative.com/blog/feed/",
        "https://blog.malwarebytes.com/feed/",
        "https://news.sophos.com/en-us/category/serious-security/feed/",
        "https://www.proofpoint.com/us/rss.xml",
        "https://googleprojectzero.blogspot.com/feeds/posts/default"
    ]
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    api_endpoint = "https://cveawg.mitre.org/api/cve/{}"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

    logger.info("Starting fetch_cves")
    with app.app_context():  # Ensure app context for database access
        try:
            init_db()
        except Exception as e:
            logger.error(f"init_db failed in fetch_cves: {e}")
            return  # Exit early on failure

        total_articles = 0
        for feed_url in rss_feeds:
            feed = feedparser.parse(feed_url)
            total_articles += min(len(feed.entries), 5) if feed.entries else 0
        progress['total'] = total_articles
        progress['completed'] = 0
        progress['done'] = False
        logger.info(f"Total articles to process: {total_articles}")

        for feed_url in rss_feeds:
            feed = feedparser.parse(feed_url)
            logger.info(f"Processing feed: {feed_url}")
            for entry in feed.entries[:5]:
                if not hasattr(entry, 'link') or not entry.link:
                    logger.warning(f"Skipping entry with no link: {entry.get('title', 'No title')}")
                    progress['completed'] += 1
                    continue

                article_url = entry.link
                logger.info(f"Fetching article: {article_url}")
                try:
                    response = requests.get(article_url, headers=headers, timeout=10)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')
                    article_text = soup.get_text(separator=' ')
                    cves = set(cve_pattern.findall(article_text))
                    if not cves:
                        logger.info(f"No CVEs found in article: {article_url}")
                    else:
                        logger.info(f"Article {article_url}: Found {len(cves)} CVEs - {cves}")
                except Exception as e:
                    logger.error(f"Failed to fetch or parse article {article_url}: {e}")
                    progress['completed'] += 1
                    continue

                for cve_id in cves:
                    try:
                        cve_id = cve_id.upper()
                        existing_cve = CVE.query.filter_by(cve_id=cve_id).first()
                        if existing_cve:
                            articles = json.loads(existing_cve.news_articles or '[]')
                            if article_url not in articles:
                                articles.append(article_url)
                                existing_cve.news_articles = json.dumps(articles)
                                existing_cve.date_imported = datetime.utcnow()
                                db.session.commit()
                        else:
                            response = requests.get(api_endpoint.format(cve_id), headers=headers, timeout=10)
                            if response.status_code == 200:
                                data = response.json()
                                pub_date_str = data.get('cveMetadata', {}).get('datePublished')
                                if pub_date_str:
                                    try:
                                        pub_date = datetime.strptime(pub_date_str, '%Y-%m-%dT%H:%M:%S.%fZ').date()
                                    except ValueError:
                                        pub_date = datetime.strptime(pub_date_str, '%Y-%m-%dT%H:%M:%S').date()
                                else:
                                    pub_date = datetime.today().date()
                                description = data.get('containers', {}).get('cna', {}).get('descriptions', [{}])[0].get('value', 'No description')
                                metrics = data.get('containers', {}).get('cna', {}).get('metrics', [])
                                severity = None
                                if metrics and 'cvss ravenV3_1' in metrics[0]:
                                    severity = metrics[0]['cvssV3_1'].get('baseScore')
                                elif metrics and 'cvssV3_0' in metrics[0]:
                                    severity = metrics[0]['cvssV3_0'].get('baseScore')
                            else:
                                description = "Awaiting full analysis"
                                severity = None
                                pub_date = datetime.today().date()

                            new_cve = CVE(
                                cve_id=cve_id,
                                description=description,
                                severity=severity,
                                publication_date=pub_date,
                                news_articles=json.dumps([article_url]),
                                date_imported=datetime.utcnow()
                            )
                            db.session.add(new_cve)
                            db.session.commit()
                    except Exception as e:
                        logger.error(f"Error processing CVE {cve_id}: {e}")
                        db.session.rollback()
                        continue
                progress['completed'] += 1
                logger.info(f"Progress: {progress['completed']}/{progress['total']}")
        progress['done'] = True
        logger.info("Fetch complete")

@app.route('/')
def home():
    return render_template('home.html')

@cache.memoize(timeout=3600)
def get_article_title(url):
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        title_tag = soup.find('title')
        return title_tag.text.strip() if title_tag else 'Untitled'
    except Exception as e:
        logger.warning(f"Failed to fetch title for {url}: {e}")
        return 'Untitled'

@app.route('/cve-list')
def cve_list():
    try:
        with app.app_context():
            init_db()
            filter_today = request.args.get('filter_today', 'false').lower() == 'true'
            filter_this_week = request.args.get('filter_this_week', 'false').lower() == 'true'
            filter_rest = request.args.get('filter_rest', 'false').lower() == 'true'
            sort_by_severity = request.args.get('sort_by_severity', 'false').lower() == 'true'

            query = CVE.query

            if filter_today:
                today = date.today()
                query = query.filter(CVE.date_imported >= datetime.combine(today, datetime.min.time()),
                                    CVE.date_imported < datetime.combine(today + timedelta(days=1), datetime.min.time()))
            elif filter_this_week:
                today = date.today()
                start_of_week = today - timedelta(days=today.weekday())
                end_of_week = start_of_week + timedelta(days=7)
                query = query.filter(CVE.date_imported >= datetime.combine(start_of_week, datetime.min.time()),
                                    CVE.date_imported < datetime.combine(end_of_week, datetime.min.time()))
            elif filter_rest:
                start_of_week = date.today() - timedelta(days=date.today().weekday())
                query = query.filter(CVE.date_imported < datetime.combine(start_of_week, datetime.min.time()))

            if sort_by_severity:
                query = query.order_by(CVE.severity.desc().nullslast(), CVE.publication_date.desc())
            else:
                query = query.order_by(CVE.publication_date.desc(), CVE.severity.desc())

            cves = query.all()
            keywords = [kw.word.lower() for kw in Keyword.query.all()]
            rss_feeds_priority = [
                "https://www.bleepingcomputer.com/feed/",
                "https://www.darkreading.com/rss.xml",
                "https://www.threatpost.com/feed/",
                "https://www.schneier.com/feed/atom/",
                "https://www.krebsonsecurity.com/feed/",
                "https://www.infosecurity-magazine.com/rss/news/",
                "https://news.ycombinator.com/rss",
                "https://www.sentinelone.com/labs/feed/",
                "https://www.zdnet.com/topic/security/rss.xml",
                "https://www.csoonline.com/feed",
                "https://securelist.com/feed/",
                "https://blog.talosintelligence.com/rss/",
                "https://msrc-blog.microsoft.com/feed/",
                "https://blog.qualys.com/feed",
                "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
                "https://www.cisa.gov/uscert/ncas/alerts.xml",
                "https://isc.sans.edu/rssfeed.xml",
                "https://www.zerodayinitiative.com/rss/upcoming/",
                "https://www.zerodayinitiative.com/rss/published/",
                "https://www.zerodayinitiative.com/blog/feed/",
                "https://blog.malwarebytes.com/feed/",
                "https://news.sophos.com/en-us/category/serious-security/feed/",
                "https://www.proofpoint.com/us/rss.xml",
                "https://googleprojectzero.blogspot.com/feeds/posts/default"
            ]

            highlighted_cves = []
            for cve in cves:
                desc = cve.description or ''
                should_highlight = False
                for keyword in keywords:
                    if keyword in desc.lower():
                        should_highlight = True
                        desc = re.sub(re.escape(keyword), f'<span class="keyword-match">{keyword}</span>', desc, flags=re.IGNORECASE)
                articles = json.loads(cve.news_articles or '[]')
                article_title = 'Untitled'
                if articles:
                    prioritized_articles = sorted(articles, key=lambda url: rss_feeds_priority.index(url) if url in rss_feeds_priority else len(rss_feeds_priority))
                    top_article = prioritized_articles[0]
                    article_title = get_article_title(top_article)
                highlighted_cves.append({
                    'cve_id': cve.cve_id,
                    'news_title': article_title,
                    'summary': desc,
                    'severity': cve.severity if cve.severity else 'N/A',
                    'publication_date': cve.publication_date if cve.publication_date else 'N/A',
                    'links': articles,
                    'date_imported': cve.date_imported.strftime('%Y-%m-%d %H:%M:%S') if cve.date_imported else 'N/A',
                    'should_highlight': should_highlight
                })
            return render_template('index.html', cves=highlighted_cves, filter_today=filter_today, filter_this_week=filter_this_week, filter_rest=filter_rest, sort_by_severity=sort_by_severity)
    except Exception as e:
        logger.error(f"Error in cve_list: {e}")
        return "Database error—please try updating the list or contact support.", 500

@app.route('/update')
def update():
    global progress
    try:
        logger.info("Manual update requested")
        progress['total'] = 0
        progress['completed'] = 0
        progress['done'] = False
        fetch_cves()
        return redirect(url_for('cve_list'))
    except Exception as e:
        logger.error(f"Update failed in route: {e}")
        return "Error during update", 500

@app.route('/progress')
def get_progress():
    percentage = (progress['completed'] / progress['total'] * 100) if progress['total'] > 0 else 0
    done = progress['done']
    logger.info(f"Progress check: {progress['completed']}/{progress['total']} = {percentage}%")
    return jsonify({'percentage': percentage, 'done': done})

@app.route('/keywords', methods=['GET', 'POST'])
def keywords():
    try:
        with app.app_context():
            init_db()
            if request.method == 'POST':
                if 'keyword' in request.form:
                    keyword = request.form.get('keyword', '').strip().lower()
                    if keyword and not Keyword.query.filter_by(word=keyword).first():
                        db.session.add(Keyword(word=keyword))
                        db.session.commit()
                elif 'delete_id' in request.form:
                    keyword = Keyword.query.get(request.form.get('delete_id'))
                    if keyword:
                        db.session.delete(keyword)
                        db.session.commit()
                return redirect(url_for('keywords'))
            keywords = Keyword.query.all()
            return render_template('keywords.html', keywords=keywords)
    except Exception as e:
        logger.error(f"Error in keywords: {e}")
        return "Database error—please try again.", 500

@app.route('/wipe-db', methods=['POST'])
def wipe_db():
    try:
        with app.app_context():
            db.drop_all()
            db.create_all()
        return redirect(url_for('cve_list'))
    except Exception as e:
        logger.error(f"Error wiping database: {e}")
        return "Error wiping database", 500

# Global scheduler instance to ensure it persists
scheduler = BackgroundScheduler()

def schedule_daily_update():
    global scheduler
    if not scheduler.running:
        trigger = CronTrigger(hour=5, minute=0)  # 5:00 AM daily, local server time
        scheduler.add_job(fetch_cves, trigger, id='daily_cve_update', replace_existing=True)
        scheduler.start()
        logger.info("Scheduled daily CVE update at 5:00 AM local time")
    else:
        logger.info("Scheduler already running, skipping re-initialization")

# Initialize database and scheduler on startup
try:
    with app.app_context():
        init_db()
    schedule_daily_update()
except Exception as e:
    logger.error(f"Startup error: {e}")

if __name__ == '__main__':
    # Ensure scheduler shuts down cleanly on exit
    import atexit
    atexit.register(lambda: scheduler.shutdown() if scheduler.running else None)
    app.run(host='0.0.0.0', port=5000, debug=False)  # Disable debug for production