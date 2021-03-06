/*
 Copyright (c) 2019 Mathieu Laurendeau <mat.lau@laposte.net>
 License: GPLv3
 */

#ifndef GPRIO_H_
#define GPRIO_H_

/*
 * Adjust OS-specific settings to increase both thread priority and scheduling.
 */
int gprio_init();

/*
 * Restore the settings changed by gprio_init.
 */
int gprio_clean();

#endif /* GPRIO_H_ */
