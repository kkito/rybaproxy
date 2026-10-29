import { fmtBytes, sparkline } from './format.js';

export interface DayStat { day: string; bytes_up: number; bytes_down: number; sessions: number }
export interface Metrics { total_sessions?: number; errors?: number; dropped?: number }

export function heatLevel(frac: number): number {
  return frac < 0.25 ? 0 : frac < 0.5 ? 1 : frac < 0.8 ? 2 : 3;
}

export interface HeroValues { sessions: string; up: string; upSpark: string; down: string; bwSpark: string; errors: string; trend: string }

export function heroValues(m: Metrics, daily: DayStat[]): HeroValues {
  const today = daily[daily.length - 1] || { bytes_up: 0, bytes_down: 0 };
  const bw = daily.map(d => (+d.bytes_up) + (+d.bytes_down));
  return {
    sessions: String(m.total_sessions ?? 0),
    up: fmtBytes(today.bytes_up),
    upSpark: sparkline(daily.map(d => +d.bytes_up)),
    down: fmtBytes(today.bytes_down),
    bwSpark: sparkline(bw),
    errors: String((+(m.errors ?? 0)) + (+(m.dropped ?? 0))),
    trend: (+(m.dropped ?? 0)) + ' 丢弃',
  };
}
