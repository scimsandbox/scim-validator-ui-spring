/*
 * Shared Ecosystem News indicator for the right-side quick-navigation dock in SCIM Validation.
 * Checks /news/index.json and compares against the shared .scimsandbox.net cookie
 * to highlight unread updates.
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
        const feedUrl = btn.getAttribute('data-news-feed-url');
        if (!feedUrl) return;
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

        // Re-check on return from the website tab, which sets the cookie. focus covers a visible
        // window regaining focus; visibilitychange covers tab switches. Re-applying is idempotent.
        window.addEventListener('focus', applyBadgeState);
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
                applyBadgeState();
            }
        });

        fetch(feedUrl, { credentials: 'omit' })
            .then((res) => (res.ok ? res.json() : null))
            .then((data) => {
                if (!Array.isArray(data) || data.length === 0) return;
                cachedItems = data
                    .map((item) => ({ item, ms: Date.parse(item && item.publishedAt) }))
                    .filter((entry) => Number.isFinite(entry.ms))
                    .sort((a, b) => b.ms - a.ms)
                    .map((entry) => entry.item);
                applyBadgeState();
            })
            .catch(() => {
                // Feed unavailable: keep the neutral "What's New" state rather than flag stale news.
            });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initDockNewsIndicator);
    } else {
        initDockNewsIndicator();
    }
})();
