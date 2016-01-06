/*
Copyright (C) 2001 Paul Davis
Copyright (C) 2004 Grame

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#ifndef __JackIoAudioDriver__
#define __JackIoAudioDriver__

#include "JackAudioDriver.h"
#include "JackThreadedDriver.h"
#include "JackTime.h"
#include "ioaudio_backend.h"

namespace Jack
{

/*!
\brief The IoAudio driver.
*/

class JackIoAudioDriver : public JackAudioDriver
{

    private:

        jack_driver_t* fDriver;

        void UpdateLatencies();

    public:

        JackIoAudioDriver(const char* name, const char* alias, JackLockedEngine* engine, JackSynchro* table)
                : JackAudioDriver(name, alias, engine, table),fDriver(NULL)
        {}
        virtual ~JackIoAudioDriver()
        {}

        int Open(ioaudio_driver_args_t args);

        int Close();
        int Attach();
        int Detach();

        int Start();
        int Stop();

        int Read();
        int Write();

        // BufferSize can be changed
        bool IsFixedBufferSize()
        {
            return false;
        }

        int SetBufferSize(jack_nframes_t buffer_size);

        void ReadInputAux(jack_nframes_t orig_nframes, ssize_t contiguous, ssize_t nread);
        void MonitorInputAux();
        void ClearOutputAux();
        void WriteOutputAux(jack_nframes_t orig_nframes, ssize_t contiguous, ssize_t nwritten);
        void SetTimetAux(jack_time_t time);

        // JACK API emulation for the midi driver
        int is_realtime() const;
        int create_thread(pthread_t *thread, int prio, int rt, void *(*start_func)(void*), void *arg);

        jack_port_id_t port_register(const char *port_name, const char *port_type, unsigned long flags, unsigned long buffer_size);
        int port_unregister(jack_port_id_t port_index);
        void* port_get_buffer(int port, jack_nframes_t nframes);
        int port_set_alias(int port, const char* name);

        jack_nframes_t get_sample_rate() const;
        jack_nframes_t frame_time() const;
        jack_nframes_t last_frame_time() const;
};

} // end of namespace

#endif
