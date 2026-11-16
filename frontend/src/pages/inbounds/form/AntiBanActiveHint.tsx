import { Alert } from 'antd';
import { useTranslation } from 'react-i18next';

type AntiBanActiveHintProps = {
  /**
   * Whether the panel-level AntiBan hardening is enabled. The flag is passed
   * in by the caller (the inbounds page reads it from the panel settings) so
   * that this component never needs a query client and can be rendered
   * anywhere, including storybook.
   */
  enabled?: boolean;
};

/**
 * AntiBanActiveHint tells the admin that the panel-level AntiBan hardening is
 * enabled. With it on, the panel rewrites saved VLESS+REALITY inbounds (Vision
 * flow, random shortId, SNI derived from the REALITY target) and hardens every
 * generated share link, so the notice explains why the editor may differ from
 * what was typed.
 */
export default function AntiBanActiveHint({ enabled = false }: AntiBanActiveHintProps) {
  const { t } = useTranslation();

  if (!enabled) return null;

  return (
    <div className="mt-12" data-testid="antiban-active-hint">
      <Alert
        type="info"
        showIcon
        title={t('pages.inbounds.antibanActive')}
        description={t('pages.inbounds.antibanActiveDesc')}
      />
    </div>
  );
}
