'use strict';

/**
 * A page of a list operation, and iteration over every item of a list. Each page is fetched like any other
 * call: signed, verified and checked (test-vectors/pagination-v1.json).
 */

const { paginate } = require('./pagination');
const { PaginationError } = require('./errors');

const declares = (operation, name) => operation.params.some(param => param.name === name && param.in === 'query');

/**
 * The paginate() options and page fetcher for one operation and call.
 *
 * @param {Object} operation
 * @param {Object} params the call's params; startingAfter in them starts mid-list
 * @param {function(Object): Promise<Page>} request makes one call with the given params
 * @param {{ limit?: number, maxItems?: number, first?: Page }} options first: a page already fetched, served
 *        as the first page instead of asking again
 */
function pagingOf(operation, params, request, { limit, maxItems, first } = {}) {
    if (operation.paging !== 'cursor' && operation.paging !== 'offset') {
        throw new PaginationError('not_paged', `${operation.operationId} does not return pages`);
    }
    if (operation.paging === 'cursor' && typeof operation.cursorField !== 'string') {
        // getAddressBalance: the docs don't name the item field to continue from. Guessing could skip or
        // repeat items, so the SDK does not page it; pass startingAfter yourself.
        throw new PaginationError('cursor_unknown', `which item field continues ${operation.operationId} is not documented, so it can't be paged automatically`);
    }
    let pending = first || null;
    const fetchPage = async ({ startingAfter, offset, limit: pageLimit }) => {
        if (pending) {
            const page = pending;
            pending = null;

            return page;
        }
        const next = { ...params };
        if (declares(operation, 'limit')) {
            next.limit = pageLimit;
        }
        if (operation.paging === 'cursor') {
            next.startingAfter = startingAfter === null ? params.startingAfter : startingAfter;
        } else if (declares(operation, 'offset')) {
            next.offset = offset;
        } else if (offset > 0) {
            // An offset-paged answer without an offset parameter fits in one page (listApiKeySigningKeys holds
            // at most two keys); asking again would return the same page.
            throw new PaginationError('not_paged', `${operation.operationId} takes no offset, so a second page can't be asked for`);
        }

        return request(next);
    };

    return {
        options: {
            paging: operation.paging,
            cursorField: operation.cursorField,
            limit: limit === undefined ? (first ? first.limit : null) : limit,
            maxLimit: operation.maxLimit,
            maxItems: maxItems === undefined ? null : maxItems,
        },
        fetchPage,
    };
}

/**
 * An async iterable over the items of a list. After the loop, `stop` says why it ended: 'end', 'empty_page'
 * or 'max_items'.
 */
class Pager {
    constructor(generator) {
        this.generator = generator;
        this.stop = null;
    }

    [Symbol.asyncIterator]() {
        return this;
    }

    async next() {
        const step = await this.generator.next();
        if (step.done) {
            this.stop = step.value;

            return { done: true, value: undefined };
        }

        return step;
    }

    async return(value) {
        await this.generator.return(value);

        return { done: true, value };
    }

    /** Every remaining item, in order. */
    async toArray() {
        const items = [];
        for await (const item of this) {
            items.push(item);
        }

        return items;
    }
}

class Page {
    // The call that fetched this page, kept private: only nextPage() and autoPaging() ask again with it.
    #context;

    /**
     * @param {{ operation: Object, params: Object, envelope: Object, meta: Object, request: function(Object): Promise<Page> }} init
     */
    constructor({ operation, params, envelope, meta, request }) {
        this.items = envelope.items;
        this.limit = envelope.limit;
        if (envelope.paging === 'offset') {
            this.offset = envelope.offset;
            this.total = envelope.total;
            this.hasMore = typeof envelope.total === 'number' && typeof envelope.offset === 'number'
                ? envelope.offset + envelope.items.length < envelope.total
                : false;
        } else {
            this.hasMore = envelope.hasMore;
            this.startingAfter = envelope.startingAfter;
        }
        this.meta = meta;
        this.#context = { operation, params, request };
    }

    /**
     * The next page, or null after the last one.
     *
     * @returns {Promise<Page|null>}
     * @throws {PaginationError} missing_cursor, cursor_unknown, not_paged
     */
    async nextPage() {
        const { operation, params, request } = this.#context;
        if (!this.hasMore || this.items.length === 0) {
            return null;
        }
        const next = { ...params };
        if (this.limit !== null && declares(operation, 'limit')) {
            next.limit = this.limit;
        }
        if (operation.paging === 'cursor') {
            if (typeof operation.cursorField !== 'string') {
                throw new PaginationError('cursor_unknown', `which item field continues ${operation.operationId} is not documented, so it can't be paged automatically`);
            }
            const last = this.items[this.items.length - 1];
            const cursor = last !== null && typeof last === 'object' ? last[operation.cursorField] : undefined;
            if (typeof cursor !== 'string' || cursor === '') {
                throw new PaginationError('missing_cursor', `the last item of the page has no ${operation.cursorField} to continue from`);
            }
            next.startingAfter = cursor;
        } else if (declares(operation, 'offset')) {
            next.offset = this.offset + this.items.length;
        } else {
            throw new PaginationError('not_paged', `${operation.operationId} takes no offset, so a second page can't be asked for`);
        }

        return request(next);
    }

    /**
     * Every item from this page on, fetching the following pages as the loop goes.
     *
     * @param {{ maxItems?: number }} [options]
     * @returns {Pager}
     */
    autoPaging({ maxItems } = {}) {
        const { operation, params, request } = this.#context;
        const pages = pagingOf(operation, params, request, { first: this, maxItems });

        return new Pager(paginate(pages.options, pages.fetchPage));
    }
}

module.exports = {
    Page,
    Pager,
    pagingOf,
};
