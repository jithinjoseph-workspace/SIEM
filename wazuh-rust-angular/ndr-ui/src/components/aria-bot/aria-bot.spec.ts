import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AriaBot } from './aria-bot';

describe('AriaBot', () => {
  let component: AriaBot;
  let fixture: ComponentFixture<AriaBot>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AriaBot]
    })
    .compileComponents();

    fixture = TestBed.createComponent(AriaBot);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
