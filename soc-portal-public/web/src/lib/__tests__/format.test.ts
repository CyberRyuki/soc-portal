import { describe, expect, it } from 'vitest';
import { dur, fsize, initials, nf, pct, short } from '../format';

describe('format', () => {
  it('nf formatea números con separador local', () => {
    expect(nf(1234567)).toMatch(/1.234.567/);
    expect(nf(undefined)).toBe('0');
  });
  it('short abrevia miles y millones', () => {
    expect(short(950)).toBe('950');
    expect(short(15_400)).toBe('15 k');
    expect(short(2_500_000)).toBe('2.5 M');
  });
  it('pct evita divisiones por cero', () => {
    expect(pct(1, 0)).toBe(0);
    expect(pct(1, 4)).toBe(25);
  });
  it('dur expresa minutos, horas y días', () => {
    expect(dur(null)).toBe('—');
    expect(dur(45)).toBe('45 min');
    expect(dur(190)).toBe('3 h 10 min');
    expect(dur(1440 * 2 + 240)).toBe('2 d 4 h');
  });
  it('fsize usa B, KB y MB', () => {
    expect(fsize(512)).toBe('512 B');
    expect(fsize(2048)).toBe('2.0 KB');
    expect(fsize(3 * 1048576)).toBe('3.0 MB');
  });
  it('initials toma hasta dos iniciales', () => {
    expect(initials('ana.perez')).toBe('AP');
    expect(initials('ryuki')).toBe('R');
    expect(initials('')).toBe('?');
  });
});
