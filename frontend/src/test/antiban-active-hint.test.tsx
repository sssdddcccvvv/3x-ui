import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import AntiBanActiveHint from '@/pages/inbounds/form/AntiBanActiveHint';

describe('AntiBanActiveHint', () => {
  it('tells the admin the hardened profile is applied while the toggle is on', () => {
    render(<AntiBanActiveHint enabled />);

    expect(screen.getByTestId('antiban-active-hint')).toBeInTheDocument();
  });

  it('stays out of the way while the toggle is off', () => {
    render(<AntiBanActiveHint enabled={false} />);

    expect(screen.queryByTestId('antiban-active-hint')).toBeNull();
  });

  it('renders nothing when no flag is passed at all', () => {
    render(<AntiBanActiveHint />);

    expect(screen.queryByTestId('antiban-active-hint')).toBeNull();
  });
});
