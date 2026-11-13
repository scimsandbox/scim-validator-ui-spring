/*
 * Ecosystem News indicator for the right-side quick-navigation dock.
 * Checks /news/index.json against the time the user last saw the news to highlight unread updates.
 * "Seen" is the newer of two timestamps under the same key, scim_news_seen:
 *   - the shared .scimsandbox.net cookie written by the website's news tab, and
 *   - a per-origin localStorage mark written when the dock button is clicked. The cookie is not
 *     readable from deployments outside .scimsandbox.net (previews, self-hosted), where the
 *     indicator would otherwise stay on forever.
 * Keep this file identical in scim-server-ui-spring and scim-validator-ui-spring.
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

    function readLocalSeen() {
        try {
            return window.localStorage.getItem(NEWS_STORAGE_KEY);
        } catch {
            return null; // storage blocked (privacy mode, disabled cookies)
        }
    }

    function markSeenLocally() {
        try {
            window.localStorage.setItem(NEWS_STORAGE_KEY, new Date().toISOString());
        } catch {
            // storage blocked: the cookie from the website remains the only signal
        }
    }

    function toMs(value) {
        const ms = value ? Date.parse(value) : NaN;
        return Number.isFinite(ms) ? ms : 0;
    }

    function getSeenTimestampMs() {
        return Math.max(toMs(readCookie(NEWS_STORAGE_KEY)), toMs(readLocalSeen()));
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

        // Opening the news counts as seeing it, whether or not the website's cookie is readable here.
        ['click', 'auxclick'].forEach((type) => btn.addEventListener(type, () => {
            markSeenLocally();
            applyBadgeState();
        }));

        // Re-check on return from the website tab, which sets the cookie. focus covers a visible
        // window regaining focus; visibilitychange covers tab switches. Re-applying is idempotent.
        window.addEventListener('focus', applyBadgeState);
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
                applyBadgeState();
            }
        });

        // no-cache: revalidate with the server on every load (cheap 304) so a new post shows up
        // immediately instead of after the feed's max-age / stale-while-revalidate window.
        fetch(feedUrl, { credentials: 'omit', cache: 'no-cache' })
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
