/*
 * Shared Ecosystem News indicator for the right-side quick-navigation dock in SCIM Validation.
 * Checks /news/index.json and compares against the shared .scimsandbox.net cookie
 * (with localStorage fallback) to highlight unread updates.
 */
(function () {
    const NEWS_STORAGE_KEY = 'scim_news_seen';

    function readCookie(name) {
        const prefix = name + '=';
        const parts = (document.cookie || '').split(';');
        for (let i = 0; i < parts.length; i++) {
            const c = parts[i].trim();
            if (c.indexOf(prefix) === 0) {
                try {
                    return decodeURIComponent(c.substring(prefix.length));
                } catch {
                    return c.substring(prefix.length);
                }
            }
        }
        return null;
    }

    function getSeenTimestampMs() {
        const cookieVal = readCookie(NEWS_STORAGE_KEY);
        const cMs = cookieVal ? Date.parse(cookieVal) : NaN;
        return Number.isFinite(cMs) ? cMs : 0;
    }

    function initDockNewsIndicator() {
        const btn = document.querySelector('.floating-side-btn-news');
        if (!btn) return;

        const dot = btn.querySelector('.news-unread-dot');
        const feedUrl = btn.getAttribute('data-news-feed-url') || 'https://scimsandbox.net/news/index.json';
        const FALLBACK_NEWS = [
            {
                id: '2026-11-09-full-scim-rfc-compliance',
                publishedAt: '2026-11-09T20:00:00Z',
                title: 'Full SCIM 2.0 & Extension Compliance (RFC 7643, 7644, 9865, 9967)'
            }
        ];
        let cachedItems = [];

        function applyBadgeState() {
            if (!cachedItems.length) return;
            const seenMs = getSeenTimestampMs();
            const latestMs = Date.parse(cachedItems[0].publishedAt || '');
            const hasNewNews = Number.isFinite(latestMs) && latestMs > seenMs;

            if (hasNewNews) {
                const latestTitle = cachedItems[0].title || 'Ecosystem update available';
                const shortTitle = latestTitle.length > 52 ? latestTitle.substring(0, 49) + '…' : latestTitle;
                const label = `New: ${shortTitle}`;
                btn.classList.add('has-unread-news');
                btn.setAttribute('data-tooltip', label);
                btn.setAttribute('aria-label', label);
                if (dot) dot.hidden = false;
            } else {
                btn.classList.remove('has-unread-news');
                btn.setAttribute('data-tooltip', "What's New");
                btn.setAttribute('aria-label', "What's New");
                if (dot) dot.hidden = true;
            }
        }

        window.addEventListener('focus', applyBadgeState);
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
                applyBadgeState();
            }
        });

        fetch(feedUrl, { credentials: 'omit' })
            .then((res) => (res.ok ? res.json() : null))
            .then((data) => {
                const list = Array.isArray(data) && data.length > 0 ? data : FALLBACK_NEWS;
                cachedItems = list.slice().sort((a, b) => Date.parse(b.publishedAt || 0) - Date.parse(a.publishedAt || 0));
                applyBadgeState();
            })
            .catch(() => {
                cachedItems = FALLBACK_NEWS.slice();
                applyBadgeState();
            });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initDockNewsIndicator);
    } else {
        initDockNewsIndicator();
    }
})();
