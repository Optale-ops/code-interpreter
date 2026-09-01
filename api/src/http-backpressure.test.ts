import { describe, expect, test } from 'bun:test';
import { EventEmitter } from 'node:events';
import { writeWithBackpressure } from './http-backpressure';

describe('bounded HTTP relay buffering', () => {
    test('pauses a far-side source until a stalled consumer drains', () => {
        const events = new EventEmitter();
        let pauses = 0;
        let resumes = 0;
        const source = { pause: () => { pauses += 1; }, resume: () => { resumes += 1; } };
        const destination = {
            destroyed: false,
            write: () => false,
            once: (event: 'drain', listener: () => void) => events.once(event, listener),
        };
        writeWithBackpressure(source, destination, Buffer.alloc(64 * 1024));
        expect(pauses).toBe(1);
        expect(resumes).toBe(0);
        events.emit('drain');
        expect(resumes).toBe(1);
    });

    test('does not resume after the stalled consumer closes', () => {
        const events = new EventEmitter();
        let resumes = 0;
        const source = { pause() {}, resume: () => { resumes += 1; } };
        const destination = {
            destroyed: false,
            write: () => false,
            once: (event: 'drain', listener: () => void) => events.once(event, listener),
        };
        writeWithBackpressure(source, destination, Buffer.alloc(64 * 1024));
        destination.destroyed = true;
        events.emit('drain');
        expect(resumes).toBe(0);
    });
});
