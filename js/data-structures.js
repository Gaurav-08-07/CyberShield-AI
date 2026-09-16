/* ============================================================
   data-structures.js
   Core data structures for the Cyber Threat Log Analyzer:
     • LogQueue        — Circular-buffer FIFO queue
     • ThreatHashTable — Chained hash table
     • SeverityBST     — AVL (self-balancing) binary search tree
     • EventStack      — Array-backed LIFO stack
   ============================================================ */

// ─── LogQueue ────────────────────────────────────────────────
class LogQueue {
    constructor(capacity = 500) {
        this.buffer = new Array(capacity);
        this.capacity = capacity;
        this.head = 0;          // index of the front element
        this.tail = 0;          // next free slot
        this.count = 0;
        this.totalEnqueued = 0;
        this.totalDequeued = 0;
    }

    enqueue(item) {
        if (this.count === this.capacity) {
            // Overwrite the oldest entry (auto-evict)
            this.head = (this.head + 1) % this.capacity;
            this.count--;
        }
        this.buffer[this.tail] = item;
        this.tail = (this.tail + 1) % this.capacity;
        this.count++;
        this.totalEnqueued++;
        return true;
    }

    dequeue() {
        if (this.count === 0) return null;
        const item = this.buffer[this.head];
        this.buffer[this.head] = undefined;
        this.head = (this.head + 1) % this.capacity;
        this.count--;
        this.totalDequeued++;
        return item;
    }

    peek()    { return this.count === 0 ? null : this.buffer[this.head]; }
    size()    { return this.count; }
    isEmpty() { return this.count === 0; }
    isFull()  { return this.count === this.capacity; }

    /** Return a snapshot of current items (head → tail order). */
    getItems(limit = 20) {
        const result = [];
        const n = Math.min(this.count, limit);
        for (let i = 0; i < n; i++) {
            result.push(this.buffer[(this.head + i) % this.capacity]);
        }
        return result;
    }

    getStats() {
        return {
            size: this.count,
            capacity: this.capacity,
            utilization: ((this.count / this.capacity) * 100).toFixed(1),
            totalEnqueued: this.totalEnqueued,
            totalDequeued: this.totalDequeued
        };
    }
}


// ─── ThreatHashTable ─────────────────────────────────────────
class ThreatHashTable {
    constructor(bucketCount = 128) {
        this.bucketCount = bucketCount;
        this.buckets = Array.from({ length: bucketCount }, () => []);
        this.count = 0;
        this.collisions = 0;
        this.totalLookups = 0;
    }

    /** djb2-style hash */
    _hash(key) {
        let h = 5381;
        for (let i = 0; i < key.length; i++) {
            h = ((h << 5) + h + key.charCodeAt(i)) >>> 0;
        }
        return h % this.bucketCount;
    }

    put(key, value) {
        const idx = this._hash(key);
        const bucket = this.buckets[idx];
        for (let i = 0; i < bucket.length; i++) {
            if (bucket[i].key === key) {
                bucket[i].value = value;
                return;
            }
        }
        if (bucket.length > 0) this.collisions++;
        bucket.push({ key, value });
        this.count++;
    }

    get(key) {
        this.totalLookups++;
        const idx = this._hash(key);
        const entry = this.buckets[idx].find(e => e.key === key);
        return entry ? entry.value : undefined;
    }

    has(key) { return this.get(key) !== undefined; }

    delete(key) {
        const idx = this._hash(key);
        const bucket = this.buckets[idx];
        const i = bucket.findIndex(e => e.key === key);
        if (i !== -1) { bucket.splice(i, 1); this.count--; return true; }
        return false;
    }

    /** Increment a numeric value (or create it starting at 0). */
    increment(key, amount = 1) {
        const cur = this.get(key);
        this.put(key, (cur || 0) + amount);
        return (cur || 0) + amount;
    }

    /** Return all key-value entries. */
    entries() {
        const result = [];
        for (const bucket of this.buckets) {
            for (const entry of bucket) {
                result.push({ key: entry.key, value: entry.value });
            }
        }
        return result;
    }

    /** Top-N entries by numeric value. */
    topN(n = 10) {
        return this.entries()
            .filter(e => typeof e.value === 'number')
            .sort((a, b) => b.value - a.value)
            .slice(0, n);
    }

    getLoadFactor() { return (this.count / this.bucketCount).toFixed(2); }

    getOccupiedBuckets() {
        return this.buckets.filter(b => b.length > 0).length;
    }

    /** Bucket-length distribution for visualization. */
    getBucketDistribution() {
        return this.buckets.map(b => b.length);
    }

    getStats() {
        return {
            entries: this.count,
            buckets: this.bucketCount,
            loadFactor: this.getLoadFactor(),
            collisions: this.collisions,
            occupiedBuckets: this.getOccupiedBuckets(),
            totalLookups: this.totalLookups
        };
    }
}


// ─── AVL BST Node ────────────────────────────────────────────
class AVLNode {
    constructor(event) {
        this.event    = event;
        this.severity = event.severity;
        this.left     = null;
        this.right    = null;
        this.height   = 1;
    }
}

// ─── SeverityBST (AVL tree) ─────────────────────────────────
class SeverityBST {
    constructor(maxNodes = 200) {
        this.root = null;
        this.nodeCount = 0;
        this.maxNodes = maxNodes;
        this.insertions = 0;
    }

    // ── AVL helpers ──────────────────────────────────────────
    _h(n) { return n ? n.height : 0; }
    _bf(n) { return this._h(n.left) - this._h(n.right); }
    _updH(n) { n.height = 1 + Math.max(this._h(n.left), this._h(n.right)); }

    _rotR(y) {
        const x = y.left, T = x.right;
        x.right = y; y.left = T;
        this._updH(y); this._updH(x);
        return x;
    }
    _rotL(x) {
        const y = x.right, T = y.left;
        y.left = x; x.right = T;
        this._updH(x); this._updH(y);
        return y;
    }

    _balance(node, severity) {
        this._updH(node);
        const bf = this._bf(node);
        if (bf > 1 && severity < node.left.severity)  return this._rotR(node);
        if (bf < -1 && severity >= node.right.severity) return this._rotL(node);
        if (bf > 1 && severity >= node.left.severity) {
            node.left = this._rotL(node.left);
            return this._rotR(node);
        }
        if (bf < -1 && severity < node.right.severity) {
            node.right = this._rotR(node.right);
            return this._rotL(node);
        }
        return node;
    }

    _insertNode(node, event) {
        if (!node) { this.nodeCount++; return new AVLNode(event); }
        if (event.severity < node.severity) {
            node.left = this._insertNode(node.left, event);
        } else {
            node.right = this._insertNode(node.right, event);
        }
        return this._balance(node, event.severity);
    }

    _findMin(node) {
        while (node.left) node = node.left;
        return node;
    }

    _removeMin(node) {
        if (!node.left) return node.right;
        node.left = this._removeMin(node.left);
        this._updH(node);
        const bf = this._bf(node);
        if (bf < -1) return this._rotL(node);
        return node;
    }

    insert(event) {
        this.insertions++;
        // If we hit the max, remove the lowest-severity node to keep memory bounded
        if (this.nodeCount >= this.maxNodes && this.root) {
            this.root = this._removeMin(this.root);
            this.nodeCount--;
        }
        this.root = this._insertNode(this.root, event);
    }

    /** Return all events with severity in [min, max]. */
    rangeQuery(min, max) {
        const results = [];
        this._range(this.root, min, max, results);
        return results;
    }
    _range(node, min, max, out) {
        if (!node) return;
        if (node.severity > min)  this._range(node.left, min, max, out);
        if (node.severity >= min && node.severity <= max) out.push(node.event);
        if (node.severity < max)  this._range(node.right, min, max, out);
    }

    inOrder() {
        const r = [];
        this._inOrder(this.root, r);
        return r;
    }
    _inOrder(n, r) {
        if (!n) return;
        this._inOrder(n.left, r);
        r.push(n.event);
        this._inOrder(n.right, r);
    }

    getMax() {
        let n = this.root;
        while (n && n.right) n = n.right;
        return n ? n.event : null;
    }
    getMin() {
        let n = this.root;
        while (n && n.left) n = n.left;
        return n ? n.event : null;
    }

    /** Serialize tree structure for Canvas rendering. */
    getTreeData() {
        return this._ser(this.root, 0);
    }
    _ser(node, depth) {
        if (!node || depth > 6) return null; // Cap depth for visualization
        return {
            severity: node.severity,
            type: node.event.type,
            height: node.height,
            depth,
            left: this._ser(node.left, depth + 1),
            right: this._ser(node.right, depth + 1)
        };
    }

    /** Severity distribution histogram (10 bins: 0-9, 10-19, … 90-100). */
    getSeverityDistribution() {
        const bins = new Array(10).fill(0);
        this._dist(this.root, bins);
        return bins;
    }
    _dist(node, bins) {
        if (!node) return;
        const idx = Math.min(9, Math.floor(node.severity / 10));
        bins[idx]++;
        this._dist(node.left, bins);
        this._dist(node.right, bins);
    }

    getStats() {
        return {
            nodeCount: this.nodeCount,
            treeHeight: this._h(this.root),
            maxSeverity: this.getMax()?.severity ?? 0,
            minSeverity: this.getMin()?.severity ?? 0,
            totalInsertions: this.insertions
        };
    }
}


// ─── EventStack ──────────────────────────────────────────────
class EventStack {
    constructor(maxSize = 50) {
        this.items = [];
        this.maxSize = maxSize;
        this.totalPushed = 0;
    }

    push(item) {
        if (this.items.length >= this.maxSize) {
            this.items.shift(); // evict bottom
        }
        this.items.push(item);
        this.totalPushed++;
    }

    pop() {
        return this.items.length ? this.items.pop() : null;
    }

    peek() {
        return this.items.length ? this.items[this.items.length - 1] : null;
    }

    size()    { return this.items.length; }
    isEmpty() { return this.items.length === 0; }
    depth()   { return this.items.length; }

    /** Search from top (most recent) down. */
    search(predicate) {
        for (let i = this.items.length - 1; i >= 0; i--) {
            if (predicate(this.items[i])) return this.items[i];
        }
        return null;
    }

    /** Get the last N items (top of stack first). */
    getItems(limit = 20) {
        return this.items.slice(-limit).reverse();
    }

    /** Find a chain of events matching a sequence of types. */
    findChain(typeSequence) {
        const chain = [];
        let si = 0;
        for (let i = 0; i < this.items.length && si < typeSequence.length; i++) {
            if (this.items[i].type === typeSequence[si]) {
                chain.push(this.items[i]);
                si++;
            }
        }
        return si === typeSequence.length ? chain : null;
    }

    getStats() {
        return {
            depth: this.items.length,
            maxSize: this.maxSize,
            totalPushed: this.totalPushed
        };
    }
}
