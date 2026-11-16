import '@testing-library/jest-dom/vitest';
import { act, fireEvent, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';

import { AllSetting } from '@/models/setting';
import GeneralTab from '@/pages/settings/GeneralTab';
import { renderWithProviders } from './test-utils';

async function renderGeneralTab(updateSetting: (patch: Partial<AllSetting>) => void) {
  renderWithProviders(
    <MemoryRouter initialEntries={['/settings']}>
      <GeneralTab allSetting={new AllSetting({ pageSize: 25 })} updateSetting={updateSetting} />
    </MemoryRouter>,
  );
  await act(async () => {});
}

describe('GeneralTab AntiBan toggle', () => {
  it('exposes the AntiBan switch and reports the new state', async () => {
    const updateSetting = vi.fn();

    await renderGeneralTab(updateSetting);

    const toggle = screen.getByRole('switch', { name: /antiban/i });
    expect(toggle).not.toBeChecked();

    fireEvent.click(toggle);

    expect(updateSetting).toHaveBeenCalledWith({ antibanEnable: true });
  });
});
