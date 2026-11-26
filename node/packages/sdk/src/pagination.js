'use strict';

/**
 * Paging through a list operation (test-vectors/pagination-v1.json). Each page is fetched by the caller's
 * fetchPage, which in the client is an ordinary call: signed, verified and checked like any other.
 */

const { PaginationError } = require('./errors');

/**
 * Yields every item of a list, page by page. The generator's return value says why it stopped: 'end',
 * 'empty_page' or 'max_items'.
 *
 * @param {Object} options
 * @param {'cursor'|'offset'} [options.paging='cursor']
 * @param {string} [options.cursorField] cursor paging: the item field sent as startingAfter
 *        (contract/overlay.json)
 * @param {number|null} [options.limit] page size; the operation's maximum when not given
 * @param {number} options.maxLimit the operation's largest page
 * @param {number|null} [options.maxItems] stop after this many items
 * @param {function(Object): Promise<Object>} fetchPage gets { startingAfter, limit } (cursor) or
 *        { offset, limit } (offset) and resolves to the answer's data: { items, hasMore, ... } or
 *        { items, offset, total, ... }
 * @returns {AsyncGenerator<Object, 'end'|'empty_page'|'max_items'>}
 * @throws {PaginationError} 'missing_cursor' or 'pagination_loop'
 */
async function* paginate({ paging = 'cursor', cursorField, limit = null, maxLimit, maxItems = null }, fetchPage) {
    const pageLimit = limit === null || limit === undefined ? maxLimit : limit;
    let yielded = 0;
    const full = () => maxItems !== null && maxItems !== undefined && yielded >= maxItems;

    if (paging === 'offset') {
        let offset = 0;
        for (;;) {
            const page = await fetchPage({ offset, limit: pageLimit });
            for (const item of page.items) {
                if (full()) {
                    return 'max_items';
                }
                yield item;
                yielded += 1;
            }
            if (full()) {
                return 'max_items';
            }
            offset += page.items.length;
            if (typeof page.total === 'number' && offset >= page.total) {
                return 'end';
            }
            if (page.items.length === 0) {
                return 'empty_page';
            }
        }
    }

    if (typeof cursorField !== 'string' || cursorField === '') {
        throw new TypeError('cursor paging needs the operation\'s cursorField');
    }
    let startingAfter = null;
    const used = new Set();
    for (;;) {
        const page = await fetchPage({ startingAfter, limit: pageLimit });
        for (const item of page.items) {
            if (full()) {
                return 'max_items';
            }
            yield item;
            yielded += 1;
        }
        if (full()) {
            return 'max_items';
        }
        if (page.hasMore !== true) {
            return 'end';
        }
        if (page.items.length === 0) {
            return 'empty_page';
        }
        const last = page.items[page.items.length - 1];
        const cursor = last !== null && typeof last === 'object' ? last[cursorField] : undefined;
        if (typeof cursor !== 'string' || cursor === '') {
            throw new PaginationError('missing_cursor', `the last item of the page has no ${cursorField} to continue from`);
        }
        if (used.has(cursor)) {
            throw new PaginationError('pagination_loop', `the cursor ${cursor} came back a second time; stopping instead of looping`);
        }
        used.add(cursor);
        startingAfter = cursor;
    }
}

module.exports = {
    paginate,
};
