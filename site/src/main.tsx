import { render } from 'preact';
import { BRAND } from '../../shared/brand';

render(<h1>{BRAND.name}</h1>, document.getElementById('app')!);
